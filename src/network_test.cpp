#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <csignal>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include <atomic>
#include <mutex>
#include <deque>

#include "crypto.h"
#include "telemetry.h"

#define PORT 12345
#define DOWNLINK_BUFFER_SIZE 256
#define LARGE_PACKET_BUFFER_SIZE (20 * 1024 * 1024)

static std::atomic<bool> g_run(true);

struct Connection {
    int socket;
    std::atomic<bool> active;

    Connection(int s, bool a) : socket(s), active(a) {}
};

struct EncryptedPacket {
    uint8_t data[1024];
    uint16_t len;
};

EncryptedPacket g_downlink_buffer[DOWNLINK_BUFFER_SIZE];
std::atomic<uint64_t> g_downlink_write_index(0);
std::mutex g_downlink_buffer_mutex;

std::deque<EncryptedPacket> g_archive_buffer;
std::mutex g_archive_buffer_mutex;

std::atomic<uint64_t> g_downlink_archive_index(0);
std::atomic<int> g_active_clients(0);

void signal_handler(int signum) {
    std::cout << "\nCaught signal " << signum << ", shutting down..." << std::endl;
    g_run = false;
}

// Helper to read a file into a string
static bool read_file_into_string(const std::string& path, std::string& out) {
    std::ifstream fs(path);
    if (!fs) return false;
    out.assign((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
    return true;
}

bool send_all(int sock, const void* data, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = send(sock, (const char*)data + total_sent, len - total_sent, 0);
        if (sent <= 0) {
            return false;
        }
        total_sent += sent;
    }
    return true;
}

// Override the weak HAL symbol
void telemetry_hal_on_receive(const uint8_t* data, uint16_t len, uint32_t timestamp) {
    (void)timestamp;
    radio_increment_packets_received(ANTENNA_UPLINK);

    TelemetryPacket decrypted_packet;
    SystemStatus status = crypto_decrypt_packet(data, len, &decrypted_packet);
    if (status == STATUS_SUCCESS) {
        std::cout << "Received and decrypted packet with length: " << decrypted_packet.data_length << std::endl;
    } else {
        std::cerr << "Failed to decrypt packet: " << status << std::endl;
        radio_increment_error_count(ANTENNA_UPLINK);
    }
}

void downlink_generator_thread_func() {
    while (g_run) {
        TelemetryPacket packet;
        uint8_t payload[TELEMETRY_PACKET_SIZE];
        uint16_t payload_len = 10;
        for(int i=0; i<payload_len; ++i) payload[i] = i;

        telemetry_create_packet(&packet, payload, payload_len, time(NULL));

        uint8_t encrypted_buf[1024];
        uint16_t encrypted_len = 0;
        crypto_encrypt_packet(&packet, encrypted_buf, &encrypted_len);

        {
            std::lock_guard<std::mutex> lock(g_downlink_buffer_mutex);
            uint64_t write_idx = g_downlink_write_index.load();
            g_downlink_buffer[write_idx % DOWNLINK_BUFFER_SIZE].len = encrypted_len;
            memcpy(g_downlink_buffer[write_idx % DOWNLINK_BUFFER_SIZE].data, encrypted_buf, encrypted_len);
            g_downlink_write_index++;
        }
        if (g_active_clients.load() == 0) {
            std::cout << "Generated and buffered downlink packet." << std::endl;
        } else {
            std::cout << "Generated live downlink packet for client(s)." << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void buffer_manager_thread_func() {
    while (g_run) {
        if (g_active_clients.load() == 0) {
            if (g_downlink_write_index.load() - g_downlink_archive_index.load() >= DOWNLINK_BUFFER_SIZE) {
                std::lock_guard<std::mutex> archive_lock(g_archive_buffer_mutex);
                std::lock_guard<std::mutex> downlink_lock(g_downlink_buffer_mutex);
                
                uint64_t start_idx = g_downlink_archive_index.load();
                uint64_t end_idx = g_downlink_write_index.load();
                for (uint64_t i = start_idx; i < end_idx; ++i) {
                    g_archive_buffer.push_back(g_downlink_buffer[i % DOWNLINK_BUFFER_SIZE]);
                }
                g_downlink_archive_index.store(end_idx);
                std::cout << "Archived " << (end_idx - start_idx) << " packets." << std::endl;

                while (g_archive_buffer.size() * sizeof(EncryptedPacket) > LARGE_PACKET_BUFFER_SIZE) {
                    g_archive_buffer.pop_front();
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void client_sender_thread_func(Connection* conn) {
    {
        std::lock_guard<std::mutex> lock(g_archive_buffer_mutex);
        for (const auto& pkt : g_archive_buffer) {
            uint16_t len_be = htons(pkt.len);
            if (!send_all(conn->socket, &len_be, sizeof(len_be)) || !send_all(conn->socket, pkt.data, pkt.len)) {
                conn->active = false;
                return;
            }
            radio_increment_packets_transmitted(ANTENNA_DOWNLINK);
        }
        g_archive_buffer.clear();
    }

    uint64_t next_packet_to_send = g_downlink_archive_index.load();

    while (g_run && conn->active) {
        if (next_packet_to_send < g_downlink_write_index.load()) {
            EncryptedPacket packet;
            {
                std::lock_guard<std::mutex> lock(g_downlink_buffer_mutex);
                packet = g_downlink_buffer[next_packet_to_send % DOWNLINK_BUFFER_SIZE];
            }

            uint16_t len_be = htons(packet.len);
            if (!send_all(conn->socket, &len_be, sizeof(len_be)) || !send_all(conn->socket, packet.data, packet.len)) {
                conn->active = false;
                break;
            }
            std::cout << "Sent encrypted packet to client." << std::endl;
            radio_increment_packets_transmitted(ANTENNA_DOWNLINK);
            next_packet_to_send++;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    if (conn->active) {
        conn->active = false;
    }
}

void receiver_thread_func(Connection* conn) {
    while (g_run && conn->active) {
        uint8_t buffer[1024] = {0};
        int valread = read(conn->socket, buffer, 1024);
        if (valread > 0) {
            telemetry_hal_on_receive(buffer, valread, time(NULL));
        } else {
            conn->active = false;
            break;
        }
    }
    if (conn->active) {
        conn->active = false;
    }
    g_active_clients--;
    std::cout << "Client disconnected." << std::endl;
    close(conn->socket);
    delete conn;
}

int main() {
    signal(SIGINT, signal_handler);

    SystemStatus status;

    status = radio_initialize();
    if (status != STATUS_SUCCESS) {
        std::cerr << "Radio initialization failed: " << status << std::endl;
        return 1;
    }
    std::cout << "Radio subsystem initialized." << std::endl;

    status = crypto_initialize();
    if (status != STATUS_SUCCESS) {
        std::cerr << "Crypto initialization failed: " << status << std::endl;
        return 1;
    }
    std::cout << "Crypto subsystem initialized." << std::endl;

    std::string local_key_pem, peer_key_pem;
    if (!read_file_into_string("local_private.pem", local_key_pem)) {
        std::cerr << "Failed to read local_private.pem" << std::endl;
        return 1;
    }
    if (!read_file_into_string("peer_public.pem", peer_key_pem)) {
        std::cerr << "Failed to read peer_public.pem" << std::endl;
        return 1;
    }

    status = crypto_set_local_private_key_pem(local_key_pem.c_str(), local_key_pem.length());
    if (status != STATUS_SUCCESS) {
        std::cerr << "Failed to load local private key: " << status << std::endl;
        return 1;
    }

    status = crypto_set_peer_public_key_pem(peer_key_pem.c_str(), peer_key_pem.length());
    if (status != STATUS_SUCCESS) {
        std::cerr << "Failed to load peer public key: " << status << std::endl;
        return 1;
    }
    std::cout << "Crypto keys loaded." << std::endl;

    radio_set_state(ANTENNA_UPLINK, RADIO_STATE_RECEIVING);
    radio_set_state(ANTENNA_DOWNLINK, RADIO_STATE_STANDBY);
    std::cout << "Radio states set." << std::endl;

    std::thread downlink_generator(downlink_generator_thread_func);
    std::thread buffer_manager(buffer_manager_thread_func);

    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return 1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        return 1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return 1;
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        return 1;
    }

    std::cout << "Listening on port " << PORT << std::endl;

    while (g_run) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(server_fd + 1, &readfds, NULL, NULL, &timeout);

        if ((activity < 0) && (errno != EINTR)) {
            perror("select");
        }

        if (activity > 0 && FD_ISSET(server_fd, &readfds)) {
            struct sockaddr_in client_address;
            socklen_t client_addrlen = sizeof(client_address);
            int client_socket = accept(server_fd, (struct sockaddr *)&client_address, &client_addrlen);

            if (client_socket < 0) {
                if (!g_run) break;
                perror("accept");
                continue;
            }

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_address.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::cout << "New connection from " << client_ip << ":" << ntohs(client_address.sin_port) << std::endl;

            g_active_clients++;
            Connection* conn = new Connection(client_socket, true);
            std::thread sender(client_sender_thread_func, conn);
            std::thread receiver(receiver_thread_func, conn);
            sender.detach();
            receiver.detach();
        }
    }

    close(server_fd);
    
    if (downlink_generator.joinable()) {
        downlink_generator.join();
    }
    if (buffer_manager.joinable()) {
        buffer_manager.join();
    }

    radio_shutdown();

    for (int i = 0; i < NUM_ANTENNAS; ++i) {
        Antenna antenna = static_cast<Antenna>(i);
        RadioControl radio_status;
        status = radio_get_status(antenna, &radio_status);
        if (status == STATUS_SUCCESS) {
            std::cout << "\nRadio Status (Antenna " << i << "):\n";
            std::cout << "  State: " << radio_status.current_state << std::endl;
            uint32_t khz = radio_get_frequency_khz(antenna);
            std::cout << "  Frequency: " << khz / 1000U << "." << khz % 1000U << " MHz\n";
            std::cout << "  Power: " << radio_status.config.transmit_power_dbm << " dBm\n";
            std::cout << "  Packets TX: " << radio_status.packets_transmitted << "\n";
            std::cout << "  Packets RX: " << radio_status.packets_received << "\n";
            std::cout << "  Errors: " << radio_status.error_count << "\n";
        }
    }

    std::cout << "Shutdown complete." << std::endl;

    return 0;
}

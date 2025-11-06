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
#include <iomanip>
#include <sys/select.h>
#include <cerrno>

#include "crypto.h"
#include "telemetry.h"

#define PORT 12345

static std::atomic<bool> g_run(true);

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

void receiver_thread_func(int sock) {
    std::vector<uint8_t> recv_buffer;
    
    while (g_run) {
        uint8_t temp_buffer[1024];
        int valread = read(sock, temp_buffer, sizeof(temp_buffer));
        
        if (valread > 0) {
            recv_buffer.insert(recv_buffer.end(), temp_buffer, temp_buffer + valread);
            
            while (recv_buffer.size() >= sizeof(uint16_t)) {
                uint16_t packet_len_be;
                memcpy(&packet_len_be, recv_buffer.data(), sizeof(packet_len_be));
                uint16_t packet_len = ntohs(packet_len_be);
                
                if (recv_buffer.size() >= sizeof(uint16_t) + packet_len) {
                    std::vector<uint8_t> packet_data(recv_buffer.begin() + sizeof(uint16_t), recv_buffer.begin() + sizeof(uint16_t) + packet_len);
                    
                    TelemetryPacket decrypted_packet;
                    SystemStatus status = crypto_decrypt_packet(packet_data.data(), packet_data.size(), &decrypted_packet);
                    if (status == STATUS_SUCCESS) {
                        std::cout << "Downlink: ";
                        for (uint16_t i = 0; i < decrypted_packet.data_length; ++i) {
                            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)decrypted_packet.data[i] << " ";
                        }
                        
                        std::cout << std::dec << std::endl;
                    } else {
                        std::cerr << "Failed to decrypt downlink packet: " << status << std::endl;
                    }
                    
                    recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + sizeof(uint16_t) + packet_len);
                } else {
                    break;
                }
            }
        } else if (valread == 0) {
            std::cout << "Server disconnected." << std::endl;
            g_run = false;
            break;
        } else {
            if (g_run) {
                perror("read");
            }
            g_run = false;
            break;
        }
    }
}

int main() {
    signal(SIGINT, signal_handler);

    SystemStatus status;

    status = crypto_initialize();
    if (status != STATUS_SUCCESS) {
        std::cerr << "Crypto initialization failed: " << status << std::endl;
        return 1;
    }

    std::string local_key_pem, peer_key_pem;
    if (!read_file_into_string("peer_private.pem", local_key_pem)) {
        std::cerr << "Failed to read peer_private.pem" << std::endl;
        return 1;
    }
    if (!read_file_into_string("local_public.pem", peer_key_pem)) {
        std::cerr << "Failed to read local_public.pem" << std::endl;
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

    int sock = 0;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) {
        perror("inet_pton failed");
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect failed");
        return 1;
    }
    std::cout << "Connected to server." << std::endl;

    std::thread receiver(receiver_thread_func, sock);

    while (g_run) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &timeout);

        if ((activity < 0) && (errno != EINTR)) {
            perror("select");
            break;
        }

        if (g_run && activity > 0 && FD_ISSET(STDIN_FILENO, &readfds)) {
            std::string line;
            if (std::getline(std::cin, line)) {
                if (line.empty()) continue;

                TelemetryPacket packet;
                telemetry_create_packet(&packet, (const uint8_t*)line.c_str(), line.length(), time(NULL));

                uint8_t encrypted_buf[512];
                uint16_t encrypted_len = 0;
                crypto_encrypt_packet(&packet, encrypted_buf, &encrypted_len);

                uint16_t len_be = htons(encrypted_len);
                if (!send_all(sock, &len_be, sizeof(len_be)) || !send_all(sock, encrypted_buf, encrypted_len)) {
                    perror("send failed");
                    g_run = false;
                    break;
                }
                
                TelemetryPacket decrypted_packet;
                SystemStatus dec_status = crypto_decrypt_packet(encrypted_buf, encrypted_len, &decrypted_packet);
                if (dec_status == STATUS_SUCCESS) {
                    std::cout << "Uplink: ";
                    for (uint16_t i = 0; i < decrypted_packet.data_length; ++i) {
                        std::cout << decrypted_packet.data[i];
                    }
                    std::cout << std::endl;
                } else {
                    std::cerr << "Failed to decrypt uplink packet: " << dec_status << std::endl;
                }
            } else {
                g_run = false;
                break;
            }
        }
    }

    g_run = false;
    shutdown(sock, SHUT_RDWR);
    if (receiver.joinable()) {
        receiver.join();
    }
    close(sock);

    std::cout << "Shutdown complete." << std::endl;

    return 0;
}

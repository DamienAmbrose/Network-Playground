#pragma once

void clear_and_flush_input_stream();
std::string get_address_string(sockaddr_in* address);
void cleanup_sockets_API();
int8_t startup_sockets_API();
int8_t get_socket_address(SOCKET socket, sockaddr_in& socket_address);
void clear_and_flush_input_stream();
void configure_receiver_socket(sockaddr_in* server_address);
void get_message_into(std::string MessageBuffer);
void block_until_input(SOCKET socket);
void receive_packets(SOCKET socket);
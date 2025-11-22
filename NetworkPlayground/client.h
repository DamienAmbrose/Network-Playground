#pragma once

int get_last_sockets_error();
void reset_input_stream();
std::string get_address_string(sockaddr_in* address);
void cleanup_sockets_API();
int startup_sockets_API();
int get_socket_address(SOCKET socket, sockaddr_in& socket_address);
void reset_input_stream();
void select_receiver_address(sockaddr_in* server_address);
void get_message_into(std::string& MessageBuffer);
void block_until_input(SOCKET socket);
void receive_packets(SOCKET socket);
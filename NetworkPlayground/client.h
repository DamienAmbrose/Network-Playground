#pragma once

void configure_server_socket(sockaddr_in* server_address);
void get_message(std::string MessageBuffer);
void block_until_input(SOCKET socket);
void receive_packets(SOCKET socket);
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <mutex>
#include <string>
#include "client.h"

#pragma comment(lib, "ws2_32.lib")
#define LOOPBACK_IPv4 "127.0.0.1"
#define PACKET_SIZE 1024
#define SEND_RECEIVE 1
#define RECEIVE 2
#define EXIT 3

sockaddr_in Local_Address_Placeholder;
std::atomic<bool> Receiving_Packets(false);
std::mutex Output_Stream_Lock;

int main() {
	Local_Address_Placeholder.sin_family = AF_INET;
	Local_Address_Placeholder.sin_addr.s_addr = htonl(INADDR_ANY);
	Local_Address_Placeholder.sin_port = htons(0);

	int8_t startup_result = startup_sockets_API();
	if (startup_result == SOCKET_ERROR) {
		std::cerr << "Sockets API did not start correctly. Aborting..." << std::endl;
		return 1;
	}

	do {
		unsigned short int directive;
		std::cout << 
			"Available directives include:" << std::endl <<
			"    1. Send a message and receive" << std::endl <<
			"    2. Only receive" << std::endl <<
			"    3. Cleanup sockets API and exit" << std::endl <<
			"Enter your desired directive (1 or 2 or 3): ";
		std::cin >> directive;
		clear_and_flush_input_stream();

		if (directive < 1 || directive > 3) continue;
		if (directive == EXIT) break;


		SOCKET client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (client_socket == INVALID_SOCKET) {
			std::cerr << "Socket creation failed! Aborting..." << std::endl;
			cleanup_sockets_API();
			return 1;
		}
		std::cout << "Socket creation succeeded." << std::endl;

		int bind_result = bind(client_socket, (sockaddr*)&Local_Address_Placeholder, sizeof(sockaddr_in));
		if (bind_result == SOCKET_ERROR) {
			std::cerr << "Socket binding failed! Aborting..." << std::endl;
			closesocket(client_socket);
			std::cout << "Socket successfully closed." << std::endl;
			cleanup_sockets_API();
			return 1;
		}
		std::cout << "Socket binding succeeded." << std::endl;

		sockaddr_in local_address_data;
		int8_t local_address_result = get_socket_address(client_socket, local_address_data);
		if (local_address_result == SOCKET_ERROR) {
			std::cout << "Retrieving socket information failed! Aborting..." << std::endl;
			closesocket(client_socket);
			std::cout << "Socket successfully closed." << std::endl;
			cleanup_sockets_API();
			return 1;
		}
		std::cout << "Local socket address is " << get_address_string(&local_address_data) << std::endl;


		if (directive == SEND_RECEIVE) {
			sockaddr_in target_address;
			configure_receiver_socket(&target_address);

			std::string MessageBuffer;
			get_message_into(MessageBuffer);

			sendto(
				client_socket,
				MessageBuffer.c_str(),
				MessageBuffer.length(),
				0,
				(sockaddr*)&target_address,
				sizeof(target_address)
			);
			clear_and_flush_input_stream();
			std::cout << "Message has been sent succesfully from " + get_address_string(&local_address_data) << std::endl;
		}


		std::cout << "Receiving UDP packets from network (press enter to cancel)... " << std::endl;
		Receiving_Packets = true;

		std::thread input_thread(block_until_input, client_socket);
		std::thread receiving_thread(receive_packets, client_socket);
		input_thread.join();
		receiving_thread.join();
	} while (true);

	cleanup_sockets_API();
	return 0;
}

int8_t startup_sockets_API() {
	WSADATA WSA_data;
	int startup_result = WSAStartup(MAKEWORD(2, 2), &WSA_data);
	if (startup_result != 0) {
		std::cerr << "WSAStartup failed (" << startup_result << ")!" << std::endl;
		return -1;
	}
	std::cout << "WSAStartup succeeded." << std::endl;
	return 0;
}

void cleanup_sockets_API()
{
	WSACleanup();
	std::cout << "WSACleanup succeeded." << std::endl;
}

void clear_and_flush_input_stream()
{
	std::cin.clear();
	std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
	std::cout << std::flush;
}

int8_t get_socket_address(SOCKET socket, sockaddr_in& socket_address)
{
	int socket_address_size = sizeof(sockaddr_in);
	int socket_address_result = getsockname(socket, (sockaddr*)&socket_address, &socket_address_size);
	if (socket_address_result == SOCKET_ERROR) {
		return SOCKET_ERROR;
	}
	return 0;
}

std::string get_address_string(sockaddr_in *address)
{
	char IP_address[INET_ADDRSTRLEN];
	PCSTR IP_address_result = inet_ntop(AF_INET, &(address->sin_addr), IP_address, INET_ADDRSTRLEN);
	if (IP_address_result == NULL) {
		return "";
	}
	u_short port = ntohs(address->sin_port);

	std::string address_string = "IPv4: " + std::string(IP_address) + ":" + std::to_string(port);
	return address_string;
}

void configure_receiver_socket(sockaddr_in *receiver_address) {
	// todo: make the ip protocol agnostic
	receiver_address->sin_family = AF_INET;

	std::string IP_address = LOOPBACK_IPv4;
	do {
		std::cout << "Enter IP address to bind the receiver (default 127.0.0.1): ";

		std::cin.clear();
		std::getline(std::cin, IP_address);
		if (IP_address.length() == 0) {
			IP_address = LOOPBACK_IPv4;
			break;
		}

		unsigned short int valid_IP_address = inet_pton(AF_INET, IP_address.c_str(), &receiver_address->sin_addr);
		if (valid_IP_address == 1) break;
		
		IP_address = LOOPBACK_IPv4;
		std::cerr << "    Invalid IP address format!" << std::endl;
	} while (true);

	int port = 8080;
	do {
		std::cout << "Enter port number to bind the receiver (default 8080): ";
		std::cin >> port;
		clear_and_flush_input_stream();

		if (!std::cin.fail() && port > 0 && port <= 65535) {
			receiver_address->sin_port = htons(port);
			break;
		}
		else {
			std::cerr << "    Invalid port number! Please enter a value between 1 and 65535." << std::endl;
			continue;
		}
	} while (port <= 0 || port > 65535);

	std::cout << "Receiver successfully configured on " << get_address_string(receiver_address) << std::endl;
}

void get_message_into(std::string MessageBuffer) {
	do {
		std::cout << "Enter message to send to server: ";
		std::cin >> MessageBuffer;
		if (MessageBuffer.length() > PACKET_SIZE) MessageBuffer.resize(PACKET_SIZE);
		// todo: test the overflow error again
		clear_and_flush_input_stream();

		std::cout <<
			"The following message will be sent to the server: " << std::endl <<
			MessageBuffer << std::endl <<
			"Confirm? (y/n): ";

		char confirmation;
		std::cin >> confirmation;
		if (confirmation == 'y') break;
	} while (true);
}

void block_until_input(SOCKET socket) {
	std::cin.get();

	Receiving_Packets = false;
	closesocket(socket);

	Output_Stream_Lock.lock();
	std::cout << "Socket successfully closed." << std::endl;
	Output_Stream_Lock.unlock();
}

void receive_packets(SOCKET socket) {
	char ReceiveBuffer[PACKET_SIZE];

	while (Receiving_Packets) {
		sockaddr_in sender_address;
		int address_size = sizeof(sockaddr_in);
		int bytesReceived = recvfrom(
			socket,
			ReceiveBuffer,
			sizeof(ReceiveBuffer) - 1,
			0,
			(sockaddr*)&sender_address,
			&address_size
		);

		if (!Receiving_Packets) break;
		if (bytesReceived == SOCKET_ERROR) {
			std::cerr << "Error reading packet (" << WSAGetLastError() << ")! Aborting for this packet..." << std::endl;
			continue;
		}
		ReceiveBuffer[bytesReceived] = '\0';

		Output_Stream_Lock.lock();
		std::cout << get_address_string(&sender_address) << std::endl;
		std::cout << ReceiveBuffer << std::endl;
		Output_Stream_Lock.unlock();

		std::this_thread::sleep_for(std::chrono::milliseconds(150));
	}
	Output_Stream_Lock.lock();
	std::cout << "Stopped receiving packets." << std::endl;
	Output_Stream_Lock.unlock();
}
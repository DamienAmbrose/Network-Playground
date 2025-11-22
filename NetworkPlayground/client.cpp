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

typedef enum {
	SEND_RECEIVE = 1,
	RECEIVE = 2,
	EXIT = 3
} Directives;

std::atomic<bool> Receiving_Packets(false);
std::mutex Output_Stream_Lock;

int main() {
	sockaddr_in Local_Address_Placeholder{};
	Local_Address_Placeholder.sin_family = AF_INET;
	Local_Address_Placeholder.sin_addr.s_addr = htonl(INADDR_ANY);
	Local_Address_Placeholder.sin_port = htons(0);

	const int startup_result = startup_sockets_API();
	if (startup_result == SOCKET_ERROR) {
		std::cerr << "Sockets API did not start correctly (" << get_last_sockets_error() << ")! Aborting..." << std::endl;
		return EXIT_FAILURE;
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
		if (std::cin.fail()) {
			reset_input_stream();
			continue;
		}
		reset_input_stream();

		if (directive < 1 || directive > 3) continue;
		if (directive == EXIT) break;


		SOCKET client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (client_socket == INVALID_SOCKET) {
			std::cerr << "Socket creation failed (" << get_last_sockets_error() << ")! Aborting..." << std::endl;
			cleanup_sockets_API();
			return EXIT_FAILURE;
		}
		std::cout << "Socket creation succeeded." << std::endl;

		const int bind_result = bind(client_socket, reinterpret_cast<sockaddr*>(&Local_Address_Placeholder), sizeof(Local_Address_Placeholder));
		if (bind_result == SOCKET_ERROR) {
			std::cerr << "Socket binding failed (" << get_last_sockets_error() << ")! Aborting..." << std::endl;
			closesocket(client_socket);
			std::cout << "Socket closed." << std::endl;
			cleanup_sockets_API();
			return EXIT_FAILURE;
		}
		std::cout << "Socket binding succeeded." << std::endl;

		sockaddr_in local_address_data{};
		const int local_address_result = get_socket_address(client_socket, local_address_data);
		if (local_address_result == SOCKET_ERROR) {
			std::cout << "Retrieving socket information failed (" << get_last_sockets_error() << ")! Aborting..." << std::endl;
			closesocket(client_socket);
			std::cout << "Socket closed." << std::endl;
			cleanup_sockets_API();
			return EXIT_FAILURE;
		}
		std::cout << "Local socket address is " << get_address_string(&local_address_data) << std::endl;


		if (directive == SEND_RECEIVE) {
			sockaddr_in target_address{};
			select_receiver_address(&target_address);

			std::string MessageBuffer;
			get_message_into(MessageBuffer);

			const int send_result = sendto(
				client_socket,
				MessageBuffer.c_str(),
				static_cast<int>(MessageBuffer.length()),
				0,
				reinterpret_cast<sockaddr*>(&target_address),
				sizeof(target_address)
			);
			if (send_result == SOCKET_ERROR) {
				std::cout << "Sending the message failed (" << get_last_sockets_error() << ")! Aborting..." << std::endl;
				closesocket(client_socket);
				std::cout << "Socket closed." << std::endl;
				cleanup_sockets_API();
				return EXIT_FAILURE;
			}
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
	return EXIT_SUCCESS;
}

int startup_sockets_API() {
	WSADATA WSA_data;
	const int startup_result = WSAStartup(MAKEWORD(2, 2), &WSA_data);
	if (startup_result != 0) {
		std::cerr << "WSAStartup failed (" << startup_result << ")!" << std::endl;
		return SOCKET_ERROR;
	}
	std::cout << "WSAStartup succeeded." << std::endl;
	return 0;
}

void cleanup_sockets_API()
{
	WSACleanup();
	std::cout << "WSACleanup succeeded." << std::endl;
}

void reset_input_stream()
{
	std::cin.clear();
	std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
}

int get_socket_address(SOCKET socket, sockaddr_in& socket_address)
{
	int socket_address_size = sizeof(socket_address);
	int socket_address_result = getsockname(socket, reinterpret_cast<sockaddr*>(&socket_address), &socket_address_size);
	if (socket_address_result == SOCKET_ERROR) {
		std::cout << "Retrieving socket address failed (" << get_last_sockets_error() << ")!";
		return SOCKET_ERROR;
	}
	return 0;
}

std::string get_address_string(sockaddr_in *address)
{
	char IP_address[INET_ADDRSTRLEN];
	PCSTR IP_address_result = inet_ntop(AF_INET, &(address->sin_addr), IP_address, INET_ADDRSTRLEN);
	if (IP_address_result == NULL) {
		return "<invalid>";
	}
	u_short port = ntohs(address->sin_port);

	std::string address_string = "IPv4: " + std::string(IP_address) + ":" + std::to_string(port);
	return address_string;
}

void select_receiver_address(sockaddr_in *receiver_address) {
	// todo: make the ip protocol agnostic
	receiver_address->sin_family = AF_INET;

	std::string IP_address = LOOPBACK_IPv4;
	do {
		std::cout << "Enter IP address to bind the receiver (default 127.0.0.1): ";
		std::getline(std::cin, IP_address);
		if (IP_address.length() == 0) IP_address = LOOPBACK_IPv4;

		unsigned short int valid_IP_address = inet_pton(AF_INET, IP_address.c_str(), &receiver_address->sin_addr);
		if (valid_IP_address == 1) break;
		
		IP_address = LOOPBACK_IPv4;
		std::cerr << "    Invalid IP address format!" << std::endl;
	} while (true);

	int port;
	do {
		std::cout << "Enter port number to bind the receiver: ";
		std::cin >> port;
		if (std::cin.fail()) {
			reset_input_stream();
			continue;
		}
		reset_input_stream();

		if (port > 0 && port <= 65535) {
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

void get_message_into(std::string& MessageBuffer) {
	do {
		std::cout << "Enter message to send to server: ";
		std::getline(std::cin, MessageBuffer);
		if (MessageBuffer.length() > PACKET_SIZE) { 
			std::cout << "Message exceeded maximum buffer size (" << PACKET_SIZE << "). " << MessageBuffer.length() - PACKET_SIZE << " characters will be truncated!" << std::endl;
			MessageBuffer.resize(PACKET_SIZE); 
		}

		std::cout <<
			"The following message will be sent to the server: " << std::endl <<
			MessageBuffer << std::endl <<
			"Confirm? (y/n): ";

		char confirmation;
		std::cin >> confirmation;
		reset_input_stream();
		if (confirmation == 'y' || confirmation == 'Y') break;
	} while (true);
}

void block_until_input(SOCKET socket) {
	std::cin.get();

	Receiving_Packets = false;
	closesocket(socket);

	std::lock_guard<std::mutex> lock(Output_Stream_Lock);
	std::cout << "Socket closed." << std::endl;
}

void receive_packets(SOCKET socket) {
	char ReceiveBuffer[PACKET_SIZE + 1];

	while (Receiving_Packets) {
		sockaddr_in sender_address{};
		int address_size = sizeof(sender_address);
		int bytes_received = recvfrom(
			socket,
			ReceiveBuffer,
			PACKET_SIZE,
			0,
			reinterpret_cast<sockaddr*>(&sender_address),
			&address_size
		);

		if (!Receiving_Packets) break;
		if (bytes_received == SOCKET_ERROR) {
			std::lock_guard<std::mutex> lock(Output_Stream_Lock);
			std::cerr 
				<< std::endl
				<< get_address_string(&sender_address) << std::endl
				<< "Error reading packet (" << get_last_sockets_error() << ")! Aborting for this packet..." << std::endl;
			continue;
		}

		ReceiveBuffer[bytes_received] = '\0';

		std::lock_guard<std::mutex> lock(Output_Stream_Lock);
		std::cout 
			<< std::endl 
			<< get_address_string(&sender_address) << std::endl
			<< ReceiveBuffer << std::endl;
	}
	std::lock_guard<std::mutex> lock(Output_Stream_Lock);
	std::cout << "Stopped receiving packets." << std::endl;
}

int get_last_sockets_error() {
	return WSAGetLastError();
}
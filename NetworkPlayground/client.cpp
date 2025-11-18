#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include "client.h"

#pragma comment(lib, "ws2_32.lib")
#define LOOPBACK_IPv4 "127.0.0.1"
#define PACKET_SIZE 1024
#define SEND_RECEIVE 1
#define RECEIVE 2
#define EXIT 3

std::atomic<bool> receiving(true);

int main() {
	bool running = true;
	unsigned short int directive = 1;

	WSADATA WSAData;
	int startupResult = WSAStartup(MAKEWORD(2, 2), &WSAData);
	if (startupResult != 0) {
		std::cerr << "WSAStartup failed (" << startupResult << ")!" << std::endl;
		return 1;
	}
	std::cout << "WSAStartup succeeded." << std::endl;

	do {
		std::cout << 
			"Available directives include:" << std::endl <<
			"    1. Send a message and receive" << std::endl <<
			"    2. Only receive" << std::endl <<
			"    3. Cleanup WSA and exit" << std::endl <<
			"Enter your desired directive (1 or 2 or 3): ";
		std::cin >> directive;
		std::cin.clear();
		std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

		if (directive < 1 || directive > 3) continue;
		if (directive == EXIT) break;

		SOCKET clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (clientSocket == INVALID_SOCKET) {
			WSACleanup();
			std::cerr << "Socket creation failed! Aborting..." << std::endl;
			return 1;
		}

		sockaddr_in local_address;
		local_address.sin_family = AF_INET;
		local_address.sin_addr.s_addr = htonl(INADDR_ANY);
		local_address.sin_port = htons(0);
		std::cout << "Socket creation succeeded." << std::endl;

		if (bind(clientSocket, (sockaddr*)&local_address, sizeof(local_address)) == SOCKET_ERROR) {
			closesocket(clientSocket);
			std::cout << "Socket successfully closed.\n";
			WSACleanup();
			std::cerr << "Socket binding failed! Aborting..." << std::endl;
			return 1;
		}
		std::cout << "Socket binding succeeded." << std::endl;

		if (directive == SEND_RECEIVE) {
			sockaddr_in serverAddress;
			configure_server_socket(&serverAddress);

			char MessageBuffer[PACKET_SIZE];
			get_message(MessageBuffer);

			sendto(
				clientSocket,
				MessageBuffer,
				strlen(MessageBuffer),
				0,
				(sockaddr*)&serverAddress,
				sizeof(serverAddress)
			);
			std::cout << "Message has been sent succesfully from ";
		}

		sockaddr_in socketInfo;
		int socketInfoSize = sizeof(socketInfo);
		if (getsockname(clientSocket, (sockaddr*)&socketInfo, &socketInfoSize) == SOCKET_ERROR) {
			std::cout << "N/A" << std::endl << "Retrieving socket information failed!" << std::endl;
			closesocket(clientSocket);
			std::cout << "Socket successfully closed." << std::endl;
			WSACleanup();
			std::cout << "WSACleanup succeeded." << std::endl;
			return 0;
		}

		char clientIPAddressBuffer[INET_ADDRSTRLEN];
		PCSTR clientIPAddress = inet_ntop(AF_INET, &(socketInfo.sin_addr), clientIPAddressBuffer, INET_ADDRSTRLEN);
		u_short clientfromPort = ntohs(socketInfo.sin_port);
		std::cout << "IPv4: " << clientIPAddressBuffer << ":" << clientfromPort << std::endl;

		std::cout << "Receiving UDP packets from network (press enter to cancel)... " << std::endl;
		receiving = true;
		std::thread inputThread(block_until_input, clientSocket);
		std::thread receivingThread(receive_packets, clientSocket);

		inputThread.join();
		receivingThread.join();
	} while (running);

	WSACleanup();
	std::cout << "WSACleanup succeeded." << std::endl;
	return 0;
}

void configure_server_socket(sockaddr_in *server_address) {
	// todo: make the ip protocol agnostic
	server_address->sin_family = AF_INET;

	char IP_address[INET_ADDRSTRLEN] = LOOPBACK_IPv4;
	do {
		std::cout << "Enter IP address to bind the server (default 127.0.0.1): ";

		std::cin.clear();
		std::cin.getline(IP_address, INET_ADDRSTRLEN);
		if (strlen(IP_address) == 0) {
			strncpy_s(IP_address, sizeof(IP_address), LOOPBACK_IPv4, sizeof(LOOPBACK_IPv4));
			break;
		}

		if (inet_pton(AF_INET, IP_address, &server_address->sin_addr) == 1) break;
		
		strncpy_s(IP_address, "127.0.0.1", INET_ADDRSTRLEN);
		std::cerr << "    Invalid IP address format!" << std::endl;
	} while (true);

	int port = 8080;
	do {
		std::cout << "Enter port number to bind the server (default 8080): ";
		std::cin >> port;

		if (!std::cin.fail() && port > 0 && port <= 65535) {
			server_address->sin_port = htons(port);
			break;
		}
		else {
			std::cin.clear();
			std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
			std::cerr << "    Invalid port number! Please enter a value between 1 and 65535." << std::endl;
			continue;
		}
	} while (port <= 0 || port > 65535);

	std::cout << "Server successfully configured:" << std::endl;
	std::cout << "    IPv4: " << IP_address << ":" << ntohs(server_address->sin_port) << std::endl;
}

void get_message(char MessageBuffer[]) {
	do {
		std::cout << "Enter message to send to server: ";

		std::cin.clear();
		std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
		std::cin.getline(MessageBuffer, PACKET_SIZE);

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
	std::cin.clear();
	std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
	std::cin.get();

	receiving = false;
	closesocket(socket);
	std::cout << "Socket successfully closed.\n";
}

void receive_packets(SOCKET socket) {
	char ReceiveBuffer[PACKET_SIZE];

	while (receiving) {
		sockaddr_in fromSocket;
		int sizeFromAddress = sizeof(sockaddr_in);
		int bytesReceived = recvfrom(
			socket,
			ReceiveBuffer,
			sizeof(ReceiveBuffer) - 1,
			0,
			(sockaddr*)&fromSocket,
			&sizeFromAddress
		);

		if (!receiving) break;

		char fromIPAddressBuffer[INET_ADDRSTRLEN];
		PCSTR fromIPAddress = inet_ntop(AF_INET, &(fromSocket.sin_addr), fromIPAddressBuffer, INET_ADDRSTRLEN);
		u_short fromPort = ntohs(fromSocket.sin_port);

		std::cout <<
			std::endl <<
			fromIPAddress << ":" << fromPort << std::endl;

		if (bytesReceived != SOCKET_ERROR) {
			ReceiveBuffer[bytesReceived] = '\0';
			std::cout << ReceiveBuffer << std::endl;
		}
		else {
			std::cerr << "Socket error encountered (" << WSAGetLastError() << ")! Aborting for this packet..." << std::endl;
			continue;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(150));
	}
	std::cout << "Stopped receiving packets." << std::endl;
}
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include "client.h"

#pragma comment(lib, "ws2_32.lib")
#define LOOPBACK_IPv4 "127.0.0.1"
#define PACKET_SIZE 1024

std::atomic<bool> receiving(true);

int main() {
	WSADATA WSAData;
	int startupResult = WSAStartup(MAKEWORD(2, 2), &WSAData);
	if (startupResult != 0) {
		std::cerr << "WSAStartup failed: " << startupResult << std::endl;
		return 1;
	}
	std::cout << "WSAStartup succeeded." << std::endl;

	SOCKET clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (clientSocket == INVALID_SOCKET) {
		std::cerr << "Socket creation failed!" << std::endl;
		WSACleanup();
		return 1;
	}
	std::cout << "Socket creation succeeded." << std::endl;


	// todo: make the ip protocol agnostic
	sockaddr_in serverSocket;
	serverSocket.sin_family = AF_INET;

	char IPAddress[INET_ADDRSTRLEN] = LOOPBACK_IPv4;
	int IPValidity = 0;
	do {
		std::cout << "Enter IP address to bind the server (default 127.0.0.1): ";

		std::cin.clear();
		std::cin.getline(IPAddress, INET_ADDRSTRLEN);
		if (strlen(IPAddress) == 0) {
			strncpy_s(IPAddress, sizeof(IPAddress), LOOPBACK_IPv4, sizeof(LOOPBACK_IPv4));
			break;
		}

		IPValidity = inet_pton(AF_INET, IPAddress, &serverSocket.sin_addr);

		if (IPValidity == 1) {
			break;
		}
		else {
			strncpy_s(IPAddress, "127.0.0.1", INET_ADDRSTRLEN);
			std::cerr << "    Invalid IP address format!" << std::endl;
			continue;
		}
	} while (IPValidity != 1);

	int port = 8080;
	do {
		std::cout << "Enter port number to bind the server (default 8080): ";
		std::cin >> port;

		if (!std::cin.fail() && port > 0 && port <= 65535) {
			serverSocket.sin_port = htons(port);
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
	std::cout << 
		"    IPv4 " << IPAddress << std::endl << 
		"    Port " << ntohs(serverSocket.sin_port) << std::endl;


	char MessageBuffer[PACKET_SIZE];
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

	sendto(
		clientSocket, 
		MessageBuffer, 
		strlen(MessageBuffer), 
		0, 
		(sockaddr*)&serverSocket, 
		sizeof(serverSocket)
	);
	std::cout << "Message has been sent. Receiving UDP packets from network (press enter to cancel)... " << std::endl;

	std::thread inputThread(blockUntilInput, clientSocket);
	std::thread receivingThread(receivePackets, clientSocket);
	inputThread.join();
	receivingThread.join();

	WSACleanup();
	std::cout << "WSACleanup succeeded." << std::endl;
	return 0;
}

void blockUntilInput(SOCKET socket) {
	std::cin.clear();
	std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
	std::cin.get();

	receiving = false;
	closesocket(socket);
	std::cout << "Socket successfully closed.\n";
}

void receivePackets(SOCKET socket) {
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

		if (bytesReceived != SOCKET_ERROR) {
			ReceiveBuffer[bytesReceived] = '\0';

			char fromIPAddressBuffer[INET_ADDRSTRLEN];
			PCSTR fromIPAddress = inet_ntop(AF_INET, &fromSocket, fromIPAddressBuffer, INET_ADDRSTRLEN);
			u_short fromPort = ntohs(fromSocket.sin_port);

			std::cout << 
				std::endl << 
				fromIPAddress << ":" << fromPort << std::endl << 
				ReceiveBuffer << std::endl;
		}
		else {
			std::cerr << "Socket error encountered! Aborting for this packet..." << std::endl;
			continue;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(150));
	}
	std::cout << "Stopped receiving packets.\n";
}
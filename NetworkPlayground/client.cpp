#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include "client.h"

#pragma comment(lib, "ws2_32.lib")
#define LOOPBACK_IPv4 "127.0.0.1"
#define PACKET_SIZE_BYTES 1024

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
	sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;

	char IPAddress[16] = LOOPBACK_IPv4;
	int IPValidity = 0;
	do {
		std::cout << "Enter IP address to bind the server (default 127.0.0.1): ";

		std::cin.clear();
		std::cin.getline(IPAddress, sizeof(IPAddress) / sizeof(char));
		if (strlen(IPAddress) == 0) {
			strncpy_s(IPAddress, sizeof(IPAddress), LOOPBACK_IPv4, sizeof(LOOPBACK_IPv4));
			break;
		}

		IPValidity = inet_pton(AF_INET, IPAddress, &serverAddress.sin_addr);

		if (IPValidity == 1) {
			break;
		}
		else {
			strncpy_s(IPAddress, "127.0.0.1", sizeof(IPAddress));
			std::cerr << "    Invalid IP address format!" << std::endl;
			continue;
		}
	} while (IPValidity != 1);

	int port = 8080;
	do {
		std::cout << "Enter port number to bind the server (default 8080): ";
		std::cin >> port;

		if (!std::cin.fail() && port > 0 && port <= 65535) {
			serverAddress.sin_port = htons(port);
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
	std::cout << "    IPv4 " << IPAddress << "\n    Port " << ntohs(serverAddress.sin_port) << std::endl;


	char MessageBuffer[PACKET_SIZE_BYTES];
	do {
		std::cout << "Enter message to send to server: ";

		std::cin.clear();
		std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
		std::cin.getline(MessageBuffer, sizeof(MessageBuffer) / sizeof(char));

		std::cout << "The following message will be sent to the server: " << std::endl << MessageBuffer << std::endl << "Confirm? (y/n): ";
		
		char confirmation;
		std::cin >> confirmation;
		if (confirmation == 'y') break;
	} while (true);

	sendto(
		clientSocket, 
		MessageBuffer, 
		strlen(MessageBuffer), 
		0, 
		(sockaddr*)&serverAddress, 
		sizeof(serverAddress)
	);
	std::cout << "Message has been sent. Receiving UDP packets from network (press enter to cancel)... " << std::endl;

	std::thread inputThread(blockUntilInput);
	std::thread receivingThread(receivePackets);
	inputThread.join();
	receivingThread.join();

	closesocket(clientSocket);
	std::cout << "Socket successfully closed." << std::endl;

	WSACleanup();
	std::cout << "WSACleanup succeeded." << std::endl;
	return 0;
}

void blockUntilInput() {
	std::cin.clear();
	std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
	std::cin.get();
	receiving = false;
}

void receivePackets(/*SOCKET socket*/) {
	char buffer[PACKET_SIZE_BYTES];

	while (receiving) {
		std::cout << std::endl << "Sample data packet." << std::endl;
		Sleep(500);
	}

	std::cout << "Stopped receiving packets." << std::endl;
}
#include "stdafx.h"
#ifndef UNICODE
#endif

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include "iostream"
#include "fstream"

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")\


int main(int argc, char *argv[])
{
	int iResult;
	WSADATA wsaData;

	SOCKET SendSocket = INVALID_SOCKET;
	sockaddr_in RecvAddr;
	int SenderAddrSize = sizeof (RecvAddr);

	char RecvIP[50]= "";
	unsigned short RecvPort = 0;
	unsigned short SendPort = 0;
	int BufLen = 1024;
	char RecvBuf[1024];
	char SendBuf[1024];

	if (argc == 4) {
		strcpy(RecvIP, argv[1]);
		RecvPort = atoi(argv[2]);
		SendPort = atoi(argv[3]);
	}
	else {
		std::fstream file("udp_client.cfg");
		if (file.is_open() && file.peek() != EOF) {
			printf("udp_client.cfg --- is opened\n\n"); // если открылся
			file >> RecvIP;
			file >> RecvPort;
			file >> SendPort;
		}
		else {
			printf("udp_client.cfg --- is empty or can`t be opened!\n"); // если первый символ конец файла
			printf("Enter the receiver ip address:");
			gets(RecvIP);
			printf("Enter the  receiver port number:");
			std::cin >> RecvPort;
			printf("Enter the sender port number:");
			std::cin >> SendPort;
		}
		file.close();
	}
	//----------------------
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error: %d\n", iResult);
		return 1;
	}
	//---------------------------------------------
	// Create a socket for sending data
	SendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (SendSocket == INVALID_SOCKET) {
		wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	//---------------------------------------------
	// Set port of the socket using bind option
	sockaddr_in SendAddr;	//adress of the sender
	SendAddr.sin_family = AF_INET;
	SendAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	SendAddr.sin_port = htons(SendPort); //set port
	if (SOCKET_ERROR == bind(SendSocket, (sockaddr*)&SendAddr, sizeof (SendAddr))){
		return E_FAIL;
	}
	//---------------------------------------------
	// Set up the RecvAddr structure with the IP address of
	// the receiver (in this example case "192.168.1.1")
	// and the specified port number.
	RecvAddr.sin_family = AF_INET;
	RecvAddr.sin_port = htons(RecvPort);
	RecvAddr.sin_addr.s_addr = inet_addr(RecvIP);
	while (true)
	{
		//---------------------------------------------
		// Send a datagram to the receiver
		wprintf(L"\nEnter text of the message:\n");
		gets(SendBuf);
		wprintf(L"Sending a datagram to the receiver...\n");
		iResult = sendto(SendSocket,
			SendBuf, BufLen, 0, (SOCKADDR *)& RecvAddr, sizeof (RecvAddr));
		if (iResult == SOCKET_ERROR) {
			wprintf(L"sendto failed with error: %d\n", WSAGetLastError());
			closesocket(SendSocket);
			WSACleanup();
			return 1;
		}
		//---------------------------------------------
		// Checking a check-datagram from the receiver
		iResult = recvfrom(SendSocket,
			RecvBuf, BufLen, 0, (SOCKADDR *)& RecvAddr, &SenderAddrSize);
		if (iResult == SOCKET_ERROR) {
			wprintf(L"recvfrom failed with error %d\n", WSAGetLastError());
		}
		printf("ToServer:%s\n", SendBuf);
		printf("FromServer:%s\n", RecvBuf);
		if (strcmp(RecvBuf, SendBuf) != 0) {
			printf("%s is not %s\n", RecvBuf, SendBuf);
			wprintf(L"Checking the sending status.........ERROR\n\n");
		}
		//---------------------------------------------
	}
	// When the application is finished sending, close the socket.
	wprintf(L"Finished sending. Closing socket.\n");
	iResult = closesocket(SendSocket);
	if (iResult == SOCKET_ERROR) {
		wprintf(L"closesocket failed with error: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	//---------------------------------------------
	// Clean up and quit.
	wprintf(L"Exiting.\n");
	WSACleanup();
	system("PAUSE");
	return 0;
}


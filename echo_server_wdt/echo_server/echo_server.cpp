#include "stdafx.h"
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include "iostream"

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

int main()
{
	WSADATA wsaData;

	SOCKET RecvSocket;
	sockaddr_in RecvAddr;

	unsigned short Port = 0;
	char RecvBuf[1024];
	int BufLen = 1024;

	sockaddr_in SenderAddr;
	int SenderAddrSize = sizeof (SenderAddr);
	int iResult = 0;

	//-----------------------------------------------
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error %d\n", iResult);
		return 1;
	}
	//-----------------------------------------------
	// Create a receiver socket to receive datagrams
	RecvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (RecvSocket == INVALID_SOCKET) {
		wprintf(L"socket failed with error %d\n", WSAGetLastError());
		return 1;
	}
	//-----------------------------------------------
	// Bind the socket to any address and the specified port.
	printf("Enter the port number:");
	std::cin >> Port;
	RecvAddr.sin_family = AF_INET;
	RecvAddr.sin_port = htons(Port);
	RecvAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	iResult = bind(RecvSocket, (SOCKADDR *)& RecvAddr, sizeof (RecvAddr));
	if (iResult != 0) {
		wprintf(L"bind failed with error %d\n", WSAGetLastError());
		return 1;
	}
	wprintf(L"Receiving datagrams...\n");

	while (true)
	{
		//-----------------------------------------------
		// Call the recvfrom function to receive datagrams
		// on the bound socket.
		
		iResult = recvfrom(RecvSocket,
			RecvBuf, BufLen, 0, (SOCKADDR *) &SenderAddr, &SenderAddrSize);
		if (iResult == SOCKET_ERROR) {
			wprintf(L"recvfrom failed with error %d\n", WSAGetLastError());
		}
		//-----------------------------------------------
		// Print content of buffer
		wprintf(L"\n------MESSAGE-----------------------------------------\n");
		printf("From: %s:%d\n", inet_ntoa(SenderAddr.sin_addr), ntohs(SenderAddr.sin_port)/* inet_ntoa(SenderAddr.sin_addr)*/);
		for (int i = 0; i < iResult/*sizeof(RecvBuf)*/; i++){
			printf("%c", RecvBuf[i]);
		}
		wprintf(L"------------------------------------------------------\n\n");

		//---------------------------------------------
		// Send a datagram to the receiver back
		wprintf(L"Sending a check-datagram to the receiver...\n\n");
		iResult = sendto(RecvSocket,
			RecvBuf, iResult, 0, (SOCKADDR *)& SenderAddr, sizeof (SenderAddr));
		if (iResult == SOCKET_ERROR) {
			wprintf(L"sendto failed with error: %d\n", WSAGetLastError());
			closesocket(RecvSocket);
			WSACleanup();
			return 1;
		}
	}
	
	//-----------------------------------------------
	// Close the socket when finished receiving datagrams
	wprintf(L"Finished receiving. Closing socket.\n");
	system("PAUSE");
	iResult = closesocket(RecvSocket);
	if (iResult == SOCKET_ERROR) {
		wprintf(L"closesocket failed with error %d\n", WSAGetLastError());
		return 1;
	}

	//-----------------------------------------------
	// Clean up and exit.
	wprintf(L"Exiting.\n");
	WSACleanup();
	return 0;
}

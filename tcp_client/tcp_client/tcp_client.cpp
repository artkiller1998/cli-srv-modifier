#include "stdafx.h"
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "fstream"
#include "iostream"
#include <thread>
#include <atomic>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

std::atomic_bool thr_works = ATOMIC_VAR_INIT(true);

void recvThread(SOCKET ConnectSocket, char * recvbuf,int recvbuflen, int iResult)
{
	while (thr_works)
	{
		std::fill_n(recvbuf, 512, 0);
		iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0)
			printf("FS %s\n", recvbuf);
		else if (iResult == 0) {
			printf("Connection closed\n");
			thr_works = ATOMIC_VAR_INIT(false);
		}
		Sleep(1);
	}
}

void sendThread(SOCKET ConnectSocket, char *sendbuf, int iResult, char *nickname)
{
	char msg[512] = "";

	while (thr_works)
	{
		fflush(stdin);
		gets(sendbuf);
		if (strcmp(sendbuf, "q") == 0)
		{
			thr_works = ATOMIC_VAR_INIT(false);
			break;
		}
		strcat(msg, nickname);
		strcat(msg, ": ");
		strcat(msg, sendbuf);
		iResult = send(ConnectSocket, msg, (int)strlen(msg), 0);
		printf("TS %s\n", msg);
		std::fill_n(msg, 512, 0);
		Sleep(1);
	}
}

int __cdecl main(int argc, char **argv)
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	const int BufferSize = 512;
	char sendbuf[BufferSize] = "Hi there!";
	char recvbuf[BufferSize] = "";
	int iResult;
	int recvbuflen = BufferSize;
	sockaddr_in RecvAddr;

	char RecvIP[50] = "";
	char RecvPort[20] = "";
	int SendPort = 0;
	char nickname[50] = "";

	if (argc == 4) {
		strcpy(RecvIP, argv[1]);
		strcpy(RecvPort, argv[2]);
		SendPort = atoi(argv[3]);
	}
	else {
		std::fstream file("tcp_client.cfg");
		if (file.is_open() && file.peek() != EOF) {
			printf("tcp_client.cfg --- is opened\n\n"); // ���� ��������
			file >> RecvIP;
			file >> RecvPort;
			file >> SendPort;
		}
		else {
			printf("tcp_client.cfg --- is empty or can`t be opened!\n"); // ���� ������ ������ ����� �����
			printf("Enter the receiver ip address:");
			fflush(stdin);
			gets(RecvIP);
			printf("Enter the  receiver port number:");
			fflush(stdin);
			gets(RecvPort);
			printf("Enter the sender port number:");
			std::cin >> SendPort;
		}
		file.close();
	}

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	// Initialize user
	printf("Enter your nickname:");
	fflush(stdin);
	gets(nickname);

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(RecvIP, (PCSTR) RecvPort, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}

		RecvAddr.sin_family = AF_INET;
		RecvAddr.sin_port = htons(SendPort);
		RecvAddr.sin_addr.s_addr = htonl(INADDR_ANY);

		iResult = bind(ConnectSocket, (SOCKADDR *)& RecvAddr, sizeof (RecvAddr));
		if (iResult != 0) {
			wprintf(L"bind failed with error %d\n", WSAGetLastError());
			return 1;
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	// Receive until the peer closes the connection
	BOOL l = TRUE;
	if (SOCKET_ERROR == ioctlsocket(ConnectSocket, FIONBIO, (unsigned long*)&l))
	{
		// Error
		int res = WSAGetLastError();
		return -1;
	}

	printf("Connected to the server!\nTo exit print: q\n");
	char msg[512] = "";
	strcat(msg, nickname);
	strcat(msg, ": ");
	strcat(msg, sendbuf);
	iResult = send(ConnectSocket, msg, (int)strlen(msg), 0);
	printf("TS %s\n", msg);
	//��� ������ ��� ��������� � ��������. ���������� ���� ��������� ����� ������ ��� ���������� �������������.Join ���� ���������� ������
	std::thread recv_t(recvThread, ConnectSocket, recvbuf, recvbuflen, iResult);
	std::thread send_t(sendThread, ConnectSocket, sendbuf, iResult, nickname);
	
	send_t.join();
	recv_t.join();
	
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	// cleanup
	closesocket(ConnectSocket);
	WSACleanup();
	system("PAUSE");
	return 0;
}
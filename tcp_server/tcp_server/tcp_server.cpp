#include "stdafx.h"
#undef UNICODE //use ANSI

#define WIN32_LEAN_AND_MEAN
#define MAX_CLIENTS 10

#include <windows.h> //Win32 API
#include <winsock2.h>
#include <ws2tcpip.h> // getaddrinfo
#include <stdlib.h> // EXIT FAILURE
#include <stdio.h> // gets, perror
#include "fstream" // read file
//#include "iostream" // input output

#pragma comment (lib, "Ws2_32.lib") // Need to link with Ws2_32.lib

typedef struct { //contains info about peers
	int socket;
	struct sockaddr_in addres;
} peer_t;

int main(int argc, char *argv[])
{
	WSADATA wsaData; //contains information about WS
	int iResult; //result WS operations

	SOCKET ListenSocket = INVALID_SOCKET;
	//SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL; //contains response(ответ) information about the host
	struct addrinfo hints;			//hints about the type of socket the caller 

	char Port[50] = ""; //receiver port number
	//int iSendResult;
	const int BufferSize = 512;
	char recvbuf[BufferSize] = ""; //recv
	int recvbuflen = BufferSize;
	//char buffer[1025];  //data buffer of 1K  

	sockaddr_in SenderAddr; //who connected
	int SenderAddrSize = sizeof (SenderAddr);

	if (argc == 2) { //reads port from args cmd
		strcpy(Port, argv[1]);
	}
	else {
		std::fstream file("tcp_server.cfg"); //reads port from file
		if (file.is_open() && file.peek() != EOF) {
			printf("tcp_server.cfg --- is opened\n\n"); // если открылся
			file >> Port;
		}
		else { //reads port from user keyboard
			printf("Enter the  receiver port number:");
			gets(Port);
		}
		file.close();
	}

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData); //use WS2
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints)); // fill zero hints
	hints.ai_family = AF_INET; //IPv4
	hints.ai_socktype = SOCK_STREAM; // TCP stream-sockets
	hints.ai_protocol = IPPROTO_TCP; 
	hints.ai_flags = AI_PASSIVE; // заполните мой IP-адрес за меня

	// Resolve(set) the server address and port
	iResult = getaddrinfo(NULL, (PCSTR)Port, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket, set port
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result); //finish settings, clear result

	iResult = listen(ListenSocket, SOMAXCONN);//максимальное количество соединений в очереди 128
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	printf("Waiting for incoming connections.\n");

	//int res;
	fd_set read_s; // Множество фд готовых к чтению
	fd_set write_s; // Множество... записи
	fd_set error_s; // Множество... исключит ситуац
	timeval time_out; // Таймаут

	//int opt = TRUE;
	int new_socket, client_socket[30],
		activity, i, valread, sd, ssd;
	int max_sd;
	sockaddr_in senderaddr; //who connected
	int senderaddrsize = sizeof (senderaddr);

	//initialise all client_socket[] to 0 so not checked  
	for (i = 0; i < MAX_CLIENTS; ++i)
	{
		client_socket[i] = 0;
	}

	while (TRUE)
	{
		//clear the socket set  
		FD_ZERO(&read_s);

		//add main socket to set  
		FD_SET(ListenSocket, &read_s);
		max_sd = ListenSocket;

		//add child sockets to set  
		for (i = 0; i < MAX_CLIENTS; ++i)
		{
			//socket descriptor  
			sd = client_socket[i];

			//if valid socket descriptor then add to read list  
			if (sd > 0)
				FD_SET(sd, &read_s);

			//highest file descriptor number, need it for the select function  
			if (sd > max_sd)
				max_sd = sd;
		}

		//wait for an activity on one of the sockets , timeout is NULL ,  
		//so wait indefinitely  неопределенное время
		activity = select(max_sd + 1, &read_s, NULL, NULL, NULL);

		if ((activity < 0) && (errno != EINTR)) // если сигнал прерывания произошел во время системного вызова - он игнорируется
		{
			printf("select error");
		}

		//If something happened on the main socket ,  
		//then its an incoming connection  
		if (FD_ISSET(ListenSocket, &read_s)) // сокет находится в мн-ве фд треб чтения
		{
			if ((new_socket = accept(ListenSocket, //принимаем соедиенеие
				(struct sockaddr *)&SenderAddr, (socklen_t*)&SenderAddrSize))<0)
			{
				perror("accept");
				exit(EXIT_FAILURE);
			}

			//add new socket to array of sockets  
			for (i = 0; i < MAX_CLIENTS; ++i)
			{
				//if position is empty  перебираем пока не найдем пустую ячейку
				if (client_socket[i] == 0)
				{
					client_socket[i] = new_socket; 
					printf("Count of connected clients: %d\n", i+1); //добавлен в список подключенных устройств

					break;
				}
			}
		}

		//else its some IO operation on some other socket 
		for (i = 0; i < MAX_CLIENTS; ++i)
		{
			sd = client_socket[i];

			if (FD_ISSET(sd, &read_s))
			{
				//Check if it was for closing , and also read the  
				//incoming message  
				std::fill_n(recvbuf, 512, 0);
				if ((valread = recv(sd, recvbuf, recvbuflen, 0)) == 0)
				{
					//Somebody disconnected , get his details and print  
					getpeername(sd, (struct sockaddr*)&senderaddr,(int *)&senderaddrsize);
					printf("Host disconnected , ip %s , port %d \n",
						inet_ntoa(senderaddr.sin_addr), ntohs(senderaddr.sin_port));

					//Close the socket and mark as 0 in list for reuse  
					//close(sd);
					client_socket[i] = 0;
				}

				//Echo back the message that came in and show it 
				else
				{
					getpeername(sd, (struct sockaddr*)&senderaddr,(int *)&senderaddrsize);
					wprintf(L"\n------MESSAGE-----------------------------------------\n");
					printf("From %s:%d  %s\n", inet_ntoa(senderaddr.sin_addr), ntohs(senderaddr.sin_port), recvbuf);
					wprintf(L"------------------------------------------------------\n");
					//set the string terminating NULL byte on the end  
					//of the data read  
					int j;
					for (j = 0; j < MAX_CLIENTS; ++j) // send everyone except sender
					{
						if (i == j) {
							continue;
						}
						ssd = client_socket[j];
						if (ssd != 0) {
							iResult = send(ssd, recvbuf, strlen(recvbuf), 0);
							if (iResult == SOCKET_ERROR) {
								wprintf(L"sendto failed with error: %d\n", WSAGetLastError());
								//Close the socket and mark as 0 in list for reuse  
								//close(sd);
								client_socket[i] = 0;
								WSACleanup();
								return 1;
							}
						}
					}
				}
			}
		}
	}
	return 0;
}


#include "UDPReceiver.h"

#include <iostream>
#include <sstream>

bool UDPReceiver::Init()
{
	// Structure to store the WinSock version. This is filled in
	// on the call to WSAStartup()
	WSADATA data;

	// To start WinSock, the required version must be passed to
	// WSAStartup(). This server is going to use WinSock version
	// 2 so I create a word that will store 2 and 2 in hex i.e.
	// 0x0202
	WORD version = MAKEWORD(2, 2);

	// Start WinSock
	int wsOk = WSAStartup(version, &data);
	if (wsOk != 0)
	{
		// Not ok! Get out quickly
		std::cout << "Can't start Winsock! " << wsOk << std::endl;
		return false;
	}

	// Create the master file descriptor set and zero it
	FD_ZERO(&m_master);

    return wsOk;
}

void UDPReceiver::Shutdown()
{
	// Close socket
	StopListening();

	// Message to let users know what's happening.
	std::string msg = "Server is shutting down. Goodbye\r\n";

	while (m_master.fd_count > 0)
	{
		// Get the socket number
		SOCKET sock = m_master.fd_array[0];

		// Send the goodbye message
		//Send(sock, msg);

		// Remove it from the master file list and close the socket
		FD_CLR(sock, &m_master);
		closesocket(sock);
	}

	// Shutdown winsock
	WSACleanup();
}

void UDPReceiver::Listen(std::string ipAddress, int port)
{
	// Create a socket, notice that it is a user datagram socket (UDP)
	m_socket = socket(AF_INET, SOCK_DGRAM, 0);

	// Create a server hint structure for the server
	sockaddr_in serverHint;
	serverHint.sin_addr.S_un.S_addr = ADDR_ANY; // Us any IP address available on the machine
	//serverHint.sin_addr.S_un.S_addr = ipAddress; // Us any IP address available on the machine
	serverHint.sin_family = AF_INET; // Address format is IPv4
	serverHint.sin_port = htons(port); // Convert from little to big endian

	// Try and bind the socket to the IP and port
	if (bind(m_socket, (sockaddr*)&serverHint, sizeof(serverHint)) == SOCKET_ERROR)
	{
		std::cout << "Can't bind socket! " << WSAGetLastError() << std::endl;
		return;
	}

	// add Listening socket to set
	SetIPAddress(ipAddress);
	SetIPPort(port);
	FD_SET(m_socket, &m_master);
}

void UDPReceiver::Accept(char buf[], int buf_Size)
{
	sockaddr_in client; // Use to hold the client information (port / ip address)
	int clientLength = sizeof(client); // The size of the client information
	std::stringstream ss;

	ZeroMemory(&client, clientLength); // Clear the client structure
	ZeroMemory(buf, buf_Size); // Clear the receive buffer

	// Wait for message
	int bytesIn = recvfrom(m_socket, buf, buf_Size, 0, (sockaddr*)&client, &clientLength);
	if (bytesIn == SOCKET_ERROR)
	{
		std::cerr << "Error receiving from client " << WSAGetLastError() << std::endl;
		return;
	}

	// Decrypt Message


	// Display message and client info
	char clientIp[256]; // Create enough space to convert the address byte array
	ZeroMemory(clientIp, 256); // to string of characters

	// Convert from byte array to chars
	inet_ntop(AF_INET, &client.sin_addr, clientIp, 256);

	// Display the message / who sent it
	ss << "Message recv from " << clientIp << " : " << buf << std::endl;
	std::cout << ss.str();
}


void UDPReceiver::Send(sockaddr_in clientSocket, std::string msg)
{
	int sendOk = sendto(m_socket, msg.c_str(), msg.size() + 1, 0, (sockaddr*)&clientSocket, sizeof(clientSocket));
	if (sendOk == SOCKET_ERROR)
	{
		std::cerr << "Error sending to client " << WSAGetLastError() << std::endl;
	}
}

std::string UDPReceiver::Recieve(SOCKET client, char buf[], int buf_Size)
{
	int bytesRecieved = 0;

	if (client != INVALID_SOCKET)
	{
		ZeroMemory(buf, buf_Size);

		bytesRecieved = recv(client, buf, buf_Size, 0);
		if (bytesRecieved > 0)
		{
			// Decrypt Message
			

			// Check to see if it's a command. \quit kills the server
			if (buf[0] == '\\')
			{
				// Is the command quit? 
				std::string cmd = std::string(buf, bytesRecieved);
				if (cmd == "\\quit")
				{
					//running = false;
				}
				return cmd; // return the command??? Ehh idk
			}
			return std::string(buf, 0, bytesRecieved);
		}
		if (bytesRecieved < 0)
		{
			std::cerr << "Problem Receiving Data.\n";
			// Drop the client
			closesocket(client);
			FD_CLR(client, &m_master);
			return nullptr;
		}
	}
	else
	{
		std::cerr << "Invalid Socket, Nothing to recieve.\n";
		// TODO: Data Leak
		return nullptr;
	}
	return nullptr;
}

std::string UDPReceiver::RecievePubKey(SOCKET client, char buf[], int buf_Size)
{
	return std::string();
}

void UDPReceiver::OnUpdate()
{
	fd_set copy = m_master;

	// See who's talking to us
	int socketCount = select(0, &copy, nullptr, nullptr, nullptr);

	// Loop through all the current connections / potential connect
	for (int i = 0; i < socketCount; i++)
	{
		// Makes things easy for us doing this assignment
		SOCKET sock = copy.fd_array[i];

		// Is it an inbound communication?
		if (sock == m_socket)
		{
			// Accept a new connection
			//SOCKET client = accept(listening, nullptr, nullptr);
			char buf[4096];
			Accept(buf, 4096);
		}
		else // It's an inbound message
		{
			char buf[4096];
			Recieve(sock, buf, 4096);

			// Send message to other clients, and definiately NOT the listening socket
			// Encrypt Message
			// Print Plain Text
			// Print Cypher Text

			for (int i = 0; i < m_master.fd_count; i++)
			{
				SOCKET outSock = m_master.fd_array[i];
				if (outSock != m_socket && outSock != sock)
				{
					std::ostringstream ss;
					ss << "SOCKET #" << sock << ": " << buf << "\r\n";
					// Encrypt Message

					//Send(outSock, ss.str());
				}
			}
		}
	}
}

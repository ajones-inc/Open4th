#include "TCPReceiver.h"
#include <iostream>
#include <sstream>


bool TCPReceiver::Init()
{
    WSAData data;
    WORD ver = MAKEWORD(2, 2);

    int wsInit = WSAStartup(ver, &data);
    // TODO: Inform caller of the error
    if (wsInit != 0)
    {
        std::cerr << "Can't Initilize WinSock! Quitting\n";
        return wsInit;
    }

    // Create the master file descriptor set and zero it
    FD_ZERO(&m_master);

	m_rsa.GenerateKeys();

    return wsInit;
}

void TCPReceiver::Shutdown()
{
	StopListening();

	// Message to let users know what's happening.
	std::string msg = "Server is shutting down. Goodbye\r\n";

	while (m_master.fd_count > 0)
	{
		// Get the socket number
		SOCKET sock = m_master.fd_array[0];

		// Send the goodbye message
		send(sock, msg.c_str(), msg.size() + 1, 0);

		// Remove it from the master file list and close the socket
		FD_CLR(sock, &m_master);
		closesocket(sock);
	}

	WSACleanup();
}

void TCPReceiver::Listen(std::string ipAddress, int port)
{
    // IPv4
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket != INVALID_SOCKET)
    {
        sockaddr_in hint;
        hint.sin_family = AF_INET;
        hint.sin_port = htons(m_port);
        hint.sin_addr.S_un.S_addr = INADDR_ANY;
        //inet_pton(AF_INET, m_ipAddress.c_str(), &hint.sin_addr);

        int bindOk = bind(m_socket, (sockaddr*)&hint, sizeof(hint));
        if (bindOk != SOCKET_ERROR)
        {
            int listenOk = listen(m_socket, SOMAXCONN);
            if (listenOk == SOCKET_ERROR)
            {
                std::cerr << "Failed to listen! No Connection made.\n";
            }
            // add Listening socket to set
			SetIPAddress(ipAddress);
			SetIPPort(port);
            FD_SET(m_socket, &m_master);
			std::cout << "Listening at:" << ntohs(hint.sin_addr.S_un.S_addr) << std::endl;
			std::cout << "Listening on:" << ntohs(hint.sin_port) << std::endl;
        }
    }
}

SOCKET TCPReceiver::Accept()
{
    SOCKET client = accept(m_socket, nullptr, nullptr);
    return client;
}

void TCPReceiver::Disconnect(SOCKET client)
{
	closesocket(client);
}

void TCPReceiver::Send(int clientSocket, std::string msg)
{
	send(clientSocket, msg.c_str(), msg.size() + 1, 0);
}

std::string TCPReceiver::Recieve(SOCKET client, char buf[], int buf_Size)
{
    int bytesRecieved = 0;

    if (client != INVALID_SOCKET)
    {
        ZeroMemory(buf, buf_Size);

        bytesRecieved = recv(client, buf, buf_Size, 0);
        if (bytesRecieved > 0)
        {
			// Check to see if it's a command. \quit kills the server
			if (buf[0] == '\\')
			{
				// Is the command quit? 
				std::string cmd = std::string(buf, bytesRecieved);
				if (cmd == "\\quit")
				{
					//running = false;
					return nullptr;
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

void TCPReceiver::OnUpdate()
{
	// While loop: accept and echo message back to client
	char buf[4096];
	SOCKET clientSocket = Accept();


	while (true)
	{
		ZeroMemory(buf, 4096);

		// Wait for client to send data
		std::string inCypher = Recieve(clientSocket, buf, 4096);
		
		// Encrypt
		//m_rsa.Decrypt()

		// Echo message back to client
		//send(clientSocket, buf, bytesReceived + 1, 0);
		Send(clientSocket, inCypher);

	}



	//fd_set copy = m_master;

	//// See who's talking to us
	//int socketCount = select(0, &copy, nullptr, nullptr, nullptr);

	//// Loop through all the current connections / potential connect
	//for (int i = 0; i < socketCount; i++)
	//{
	//	// Makes things easy for us doing this assignment
	//	SOCKET sock = copy.fd_array[i];

	//	// Is it an inbound communication?
	//	if (sock == m_socket) // Is it us?
	//	{
	//		// Accept a new connection
	//		std::cout << "waiting on connection.\n";
	//		SOCKET client = Accept();

	//		// Add the new connection to the list of connected clients
	//		std::cout << "Connected a client. Client handle = " << client << std::endl;
	//		FD_SET(client, &m_master);

	//		// TODO: Send Public Key
	//		CryptoPP::ByteQueue queue;
	//		m_rsa.PublicKey().Load(queue);
	//		std::string outPubkey;
	//		m_rsa.Save(outPubkey, queue);
	//		Send(client, outPubkey);
	//		
	//		// Send a welcome message to the connected client
	//		std::string welcomeMsg = "Welcome to the Awesome Chat Server!\r\n";
	//		Send(client, welcomeMsg);
	//	}
	//	else // It's an inbound message
	//	{
	//		char buf[4096];
	//		std::string inCypher = Recieve(sock, buf, 4096);

	//		// Decrypt Message
	//		std::string plainText = m_rsa.Decrypt(inCypher);

	//		// Send message to other clients, and definiately NOT the listening socket
	//		for (int i = 0; i < m_master.fd_count; i++)
	//		{
	//			SOCKET outSock = m_master.fd_array[i];
	//			if (outSock != m_socket && outSock != sock)
	//			{
	//				// Look up Public Key for outSock

	//				std::ostringstream ss;
	//				ss << "SOCKET #" << sock << ": " << plainText << "\r\n";

	//				// Encrypt message
	//				std::string outCypher = "";

	//				Send(outSock, ss.str());
	//			}
	//		}
	//	}
	//}
}




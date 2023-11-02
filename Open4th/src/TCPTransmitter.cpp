#include "TCPTransmitter.h"

#include <iostream>

bool TCPTransmitter::Init()
{
	// Initialize WinSock
	WSAData data;
	WORD ver = MAKEWORD(2, 2);
	int wsResult = WSAStartup(ver, &data);
	if (wsResult != 0)
	{
		std::cerr << "Can't start Winsock, Err #" << wsResult << std::endl;
		return false;
	}

	// Generate Keys
	m_rsa.GenerateKeys();

	return true;
}

void TCPTransmitter::Shutdown()
{
	Disconnect();
	WSACleanup();
}

void TCPTransmitter::Connect(std::string ipAddress, int port)
{
	// Create socket
	m_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (m_socket == INVALID_SOCKET)
	{
		std::cerr << "Can't create socket, Err #" << WSAGetLastError() << std::endl;
		WSACleanup();
		return;
	}
	std::cout << "Socket created\n";

	// Fill in a hint structure
	sockaddr_in hint;
	hint.sin_family = AF_INET;
	hint.sin_port = htons(port);
	hint.sin_addr.S_un.S_addr = INADDR_ANY;
	//inet_pton(AF_INET, ipAddress.c_str(), &hint.sin_addr);

	// Connect to server
	int connResult = connect(m_socket, (sockaddr*)&hint, sizeof(hint));
	if (connResult == SOCKET_ERROR)
	{
		std::cerr << "Can't connect to server, Err #" << WSAGetLastError() << std::endl;
		closesocket(m_socket);
		WSACleanup();
		return;
	}

	std::cout << "Connected\n";

	CryptoPP::ByteQueue queue;
	m_rsa.PublicKey().Load(queue);
	std::string outPubkey;
	m_rsa.Save(outPubkey, queue);
	Send(outPubkey);
}

void TCPTransmitter::Send(std::string msg)
{
	// Send the text
	int sendResult = send(m_socket, msg.c_str(), msg.size() + 1, 0);
	if (sendResult == SOCKET_ERROR)
	{
		std::cerr << "Problem sending message, Err #" << WSAGetLastError() << std::endl;
	}
}

std::string TCPTransmitter::Recieve(char buf[], int buf_Size)
{
	ZeroMemory(buf, buf_Size);
	int bytesReceived = recv(m_socket, buf, buf_Size, 0);
	std::string s(buf, 0, bytesReceived);
	if (bytesReceived > 0)
	{
		// Echo response to console
		std::cout << "SERVER> " << s << std::endl;
	}
	return s;
}

std::string TCPTransmitter::RecievePubKey(char buf[], int buf_Size)
{
	ZeroMemory(buf, buf_Size);
	int bytesReceived = recv(m_socket, buf, buf_Size, 0);
	std::string s(buf, 0, bytesReceived);
	if (bytesReceived > 0)
	{
		// Echo response to console
		std::cout << "SERVER Public Key> " << s << std::endl;
	}
	return s;
}

void TCPTransmitter::OnUpdate()
{
	// Do-while loop to send and receive data
	char buf[4096];
	std::string userInput;

	do
	{
		CryptoPP::ByteQueue queue;
		m_remotePublicKey.Load(queue);
		std::string outPubkey;
		//m_remotePublicKey.( queue);
		// Prompt the user for some text
		std::cout << "> ";
		std::getline(std::cin, userInput);

		if (userInput.size() > 0)		// Make sure the user has typed in something
		{
			// Send the text
			// Encrypt Message
			std::string outCypher = userInput;
			// Print Cypher Text
			Send(outCypher);
			// Wait for a reply
			std::string inCypher = Recieve(buf, 4096);
			// Decrypt Message
			// Print Plain Text
		}

	} while (userInput.size() > 0);
}

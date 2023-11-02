#include "UDPTransmitter.h"

#include <iostream>
#include <sstream>

bool UDPTransmitter::Init()
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

	// Gen Keys
	m_rsa.GenerateKeys();

	// Socket creation, note that the socket type is datagram
	m_socket = socket(AF_INET, SOCK_DGRAM, 0);
	return true;
}

void UDPTransmitter::Shutdown()
{
	Disconnect();
	// Shutdown winsock
	WSACleanup();
}

void UDPTransmitter::Connect(std::string ipAddress, int port)
{
	// Create a hint structure for the server
	remote_server.sin_family = AF_INET; // AF_INET = IPv4 addresses
	remote_server.sin_port = htons(port); // Little to big endian conversion
	inet_pton(AF_INET, ipAddress.c_str(), &remote_server.sin_addr); // Convert from string to byte array
}

void UDPTransmitter::Send(std::string msg)
{
	// Write out to that socket
	int sendOk = sendto(m_socket, msg.c_str(), msg.size() + 1, 0, (sockaddr*)&remote_server, sizeof(remote_server));

	if (sendOk == SOCKET_ERROR)
	{
		std::cerr << "That didn't work! " << WSAGetLastError() << std::endl;
	}
}

void UDPTransmitter::SendPubKey(CryptoPP::RSA::PublicKey pubkey, int size)
{
	//int sendOk = sendto(m_socket, msg.c_str(), size + 1, 0, (sockaddr*)&remote_server, sizeof(remote_server));
}

std::string UDPTransmitter::Recieve(char buf[], int buf_Size)
{
	sockaddr_in client; // Use to hold the client information (port / ip address)
	int clientLength = sizeof(client); // The size of the client information
	std::ostringstream ss;

	ZeroMemory(&client, clientLength); // Clear the client structure
	ZeroMemory(buf, buf_Size); // Clear the receive buffer

	// Wait for message
	int bytesIn = recvfrom(m_socket, buf, buf_Size, 0, (sockaddr*)&client, &clientLength);
	if (bytesIn == SOCKET_ERROR)
	{
		std::cerr << "Error receiving from client " << WSAGetLastError() << std::endl;
		return nullptr;
	}

	// Decrypt Message
	std::string plaintext = m_rsa.Decrypt(std::string(buf));

	// Display message and client info
	char clientIp[256]; // Create enough space to convert the address byte array
	ZeroMemory(clientIp, 256); // to string of characters

	// Convert from byte array to chars
	inet_ntop(AF_INET, &client.sin_addr, clientIp, 256);

	// Display the message / who sent it
	ss << "Message recv from " << clientIp << " : " << plaintext << std::endl;
	return ss.str();
}

std::string UDPTransmitter::RecievePubKey(char buf[], int buf_Size)
{
	return std::string();
}

void UDPTransmitter::OnUpdate()
{
	// Do-while loop to send and receive data
	char buf[4096];
	std::string userInput;

	do
	{
		// Send Public key
		std::string key;
		m_rsa.SaveKey(key, m_rsa.PublicKey());
		Send(key);
		
		// Recieve Server Public key
		std::string inRemotekey;
		//m_rsa.SaveKey(inRemotekey, Recieve(buf, MAX_BUFFER_SIZE));

		// Prompt the user for some text
		std::cout << "> ";
		// Prompt the user for some text
		std::getline(std::cin, userInput);

		if (userInput.size() > 0)		// Make sure the user has typed in something
		{
			// Encrypt message
			std::string outCiphertext = m_rsa.Encrypt(userInput);
			// Send the text
			Send(outCiphertext);

			// Wait for a reply
			std::string inPlaintext = Recieve(buf, 4096);
			if (!inPlaintext.empty())
			{
				// Do sometine with message. Save?... (Recieve already decrypts)
			}
			//userInput.clear();
		}

	} while (userInput.size() > 0);
}


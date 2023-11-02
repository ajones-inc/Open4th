#pragma once
#include "PlatformDetection.h"
#include "Request.h"

// Network Headers Windows
#ifdef OPEN4TH_PLATFORM_WINDOWS
	#include <ws2tcpip.h>
	#pragma comment (lib, "ws2_32.lib")
#elif OPEN4TH_PLATFORM_ANDROID
#elif OPEN4TH_PLATFORM_LINUX
#elif OPEN4TH_PLATFORM_IOS
#elif OPEN4TH_PLATFORM_MACOS
#endif

#include <string>

#include "crypto/Open4th_RSA.h"
#include <cryptopp/rsa.h>

// TCP Client

class UDPTransmitter
{
public:
	UDPTransmitter() = default;
	~UDPTransmitter() {}

	bool Init();
	void Shutdown();

	void Connect(std::string ipAddress, int port);
	void Disconnect() { closesocket(m_socket); }

	void Send(std::string msg);
	void SendPubKey(CryptoPP::RSA::PublicKey pubkey, int size);
	std::string Recieve(char buf[], int buf_Size);
	std::string RecievePubKey(char buf[], int buf_Size);

	void OnUpdate();

public:
	std::string GetIPAddress() { return m_ipAddress; }
	int GetPort() { return m_port; }

	void SetIPAddress(std::string adr) { m_ipAddress = adr; }
	void SetIPPort(int port) { m_port = port; }
private:
	SOCKET m_socket = 0;
	sockaddr_in remote_server;
	std::string m_ipAddress = "";
	int m_port = 0;
	Open4_RSA m_rsa;
	CryptoPP::RSA::PublicKey m_remotePublicKey;
};
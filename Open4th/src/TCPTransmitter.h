#pragma once
#include "PlatformDetection.h"
#include "Request.h"
#include "crypto/Open4th_RSA.h"

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


// TCP Client

class TCPTransmitter
{
public:
	TCPTransmitter() = default;
	~TCPTransmitter() {}

	bool Init();
	void Shutdown();

	void Connect(std::string ipAddress, int port);
	void Disconnect() { closesocket(m_socket); }

	void Send(std::string msg);
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
	std::string m_ipAddress = "";
	int m_port = 0;
	Open4_RSA m_rsa;
	CryptoPP::RSA::PublicKey m_remotePublicKey;
};
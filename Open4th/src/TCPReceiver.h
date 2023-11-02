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


// TCP Listener

class TCPReceiver
{
public:
	TCPReceiver() = default;
	~TCPReceiver() {}

	bool Init();
	void Shutdown();

	void Listen(std::string ipAddress, int port);
	void StopListening() { FD_CLR(m_socket, &m_master); closesocket(m_socket); }

	SOCKET Accept();
	void Disconnect(SOCKET client);

	void Send(int clientSocket, std::string msg);
	std::string Recieve(SOCKET client, char buf[], int buf_Size);

	void OnUpdate();

public:
	std::string GetIPAddress() { return m_ipAddress; }
	int GetPort() { return m_port; }

	void SetIPAddress(std::string adr) { m_ipAddress = adr; }
	void SetIPPort(int port) { m_port = port; }
private:
	SOCKET m_socket = 0;
	fd_set m_master;
	std::string m_ipAddress = "";
	int m_port = 0;
	Open4_RSA m_rsa;
	CryptoPP::RSA::PublicKey m_remotePublicKey;
};
#include "../Open4th.h"

#include <string>
#include <iostream>

// BootCon: 
//	- Goal:	Show Encryption = Confidentiality
// 
// Steps:
// 1) Encrypt Message
// 2) Listen for packets
// 3) Send Encrypted Message
// 4) Check Message Integraty (Plain text match && Cypher text match)
// 5) Show Intercepted packets cant be decrypted.

int main()
{
	// Create Server
	TCPReceiver server;
	server.Init();
	// Listen & Accept a Connection
	server.Listen("0.0.0.0", 54000);

	// Receive a message
	// Begin: Loop
	char buf[MAX_BUFFER_SIZE];
	// Enter a loop
	while (true)
	{
		server.OnUpdate();
	}

	// Close Connection & Shutdown
	server.Shutdown();
	return 0;
}
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
	server.Listen("127.0.0.1", 54000);

	// Receive a message
	// Begin: Loop
	char buf[MAX_BUFFER_SIZE];
	while (true)
	{
		server.OnUpdate();
	}
	// End: Loop

	// Close Connection & Shutdown
	server.Shutdown();
	return 0;
}
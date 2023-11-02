#include "../Open4th.h"

//#pragma comment(lib, "Open4th.lib")

// BootCon: 
//	- Goal:	Show Encryption = Confidentiality
// 
// Steps:
// 1) Encrypt Message
// 2) Listen for packets
// 3) Send Encrypted Message
// 4) Check Message Integraty (Plain text match && Cypher text match)
// 5) Show Intercepted packets cant be decrypted.


// Main entry point into the server
void main()
{
	UDPReceiver server;
	server.Init();
	server.Listen("127.0.0.1", 54000);

	// Enter a loop
	while (true)
	{
		server.OnUpdate();
	}
	server.Shutdown();
}
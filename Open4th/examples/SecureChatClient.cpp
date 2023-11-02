#include "../Open4th.h"

// BootCon: 
//	- Goal:	Show Encryption = Confidentiality
// 
// Steps:
// 1) Encrypt Message
// 2) Listen for packets
// 3) Send Encrypted Message
// 4) Check Message Integraty (Plain text match && Cypher text match)
// 5) Show Intercepted packets cant be decrypted.

#include <iostream>
#include <string>

//#pragma comment(lib, "Open4th.lib")

using namespace std;

void main()
{
	string ipAddress = "0.0.0.0";			// IP Address of the server
	int port = 54000;						// Listening port # on the server

	TCPTransmitter client;
	client.Init();
	client.Connect(ipAddress, port);

	// Do-while loop to send and receive data
	char buf[4096];
	string userInput;

	do
	{
		// Prompt the user for some text
		cout << "> ";
		getline(cin, userInput);

		if (userInput.size() > 0)		// Make sure the user has typed in something
		{
			// Send the text
			client.Send(userInput);
			// Wait for a reply
			client.Recieve(buf, 4096);
		}

	} while (userInput.size() > 0);

	// Gracefully close down everything
	client.Shutdown();
}
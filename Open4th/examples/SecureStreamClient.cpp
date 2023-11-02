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
//#pragma comment(lib, "Open4th.lib")



#include <iostream>


void main(int argc, char* argv[]) // We can pass in a command line option!! 
{
	UDPTransmitter client;
	client.Init();
	client.Connect("127.0.0.1", 54000);
	client.Send(std::string(argv[1]));
	client.Shutdown();
}
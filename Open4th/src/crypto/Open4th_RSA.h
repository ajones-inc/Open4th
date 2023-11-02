#pragma once
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include <cryptopp/osrng.h>

#include <string>

class Open4_RSA
{
public:
	Open4_RSA() = default;
	~Open4_RSA();

	std::string ReadFile(std::string filename);

	void GenerateKeys();
	CryptoPP::RSA::PrivateKey CreatePrivateKey(int size);
	void SaveKey(const std::string filename, const CryptoPP::RSA::PublicKey& key);
	void SaveKey(const std::string filename, const CryptoPP::RSA::PrivateKey& key);
	void Save(const std::string filename, const CryptoPP::BufferedTransformation& bt);
	void KeyString(const CryptoPP::RSA::PublicKey key, const std::string inKey);

	std::string Encrypt(std::string plaintext);
	CryptoPP::SecByteBlock Encrypt(CryptoPP::RSA::PublicKey pub_key, const std::string msg);
	CryptoPP::SecByteBlock EncryptFile(CryptoPP::RSA::PublicKey pub_key, const std::string file);

	std::string ConvertToString(CryptoPP::SecByteBlock block);
	CryptoPP::SecByteBlock ConvertToSecBlock(std::string str);

	std::string Decrypt(std::string ciphertext);
	std::string Decrypt(CryptoPP::SecByteBlock ciphertext, CryptoPP::RSA::PrivateKey priv_key);


	std::string SignMessage(std::string ciphertext);
	bool Verify(std::string ciphertext, std::string signature);

	void SaveFile(std::string filename, std::string msg);

	CryptoPP::RSA::PublicKey PublicKey() { return m_PublicKey; }

protected:
	CryptoPP::RSA::PrivateKey PrivateKey() { return m_PrivateKey; }

private:
	CryptoPP::AutoSeededRandomPool m_rng;
	CryptoPP::RSA::PrivateKey m_PrivateKey;
	CryptoPP::RSA::PublicKey m_PublicKey;
	CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Signer m_Signer;
	CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Verifier m_Verifier;
};

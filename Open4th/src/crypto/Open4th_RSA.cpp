#include "Open4th_RSA.h"
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/queue.h>
#include <cryptopp/secblockfwd.h>
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/secblock.h>

#include <sstream>
#include <assert.h>
#include <iostream>
#include <fstream>


Open4_RSA::~Open4_RSA()
{
}

std::string Open4_RSA::ReadFile(std::string filename)
{
    std::ifstream file;
    file.open(filename);
    assert(file.is_open());
    std::ostringstream sstr;
    sstr << file.rdbuf();
    return sstr.str();
}

void Open4_RSA::GenerateKeys()
{
    // Generate keys
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(m_rng, 2048);

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    std::string plain = "RSA Encryption", cipher, recovered;  
}

CryptoPP::RSA::PrivateKey Open4_RSA::CreatePrivateKey(int size)
{
    m_PrivateKey.GenerateRandomWithKeySize(m_rng, size);
    return m_PrivateKey;
}

std::string Open4_RSA::Encrypt(std::string plaintext)
{
    CryptoPP::SecByteBlock b = Encrypt(PublicKey(), plaintext);
    return ConvertToString(b);
    //// Encrypt
    //size_t cipherTextSize = m_PublicKey.CiphertextLength(plaintext.size());
    //assert(0 != cipherTextSize);
    //assert(plaintext.size() >= cipherTextSize);
    //
    //m_PublicKey.Encrypt(m_prng, (CryptoPP::byte*)plaintext, plaintext.size(), (CryptoPP::byte*)cipherText);

    //// Encryption
    //CryptoPP::RSAES_OAEP_SHA_Encryptor e(m_PublicKey);
    //std::string cipher;

    //CryptoPP::StringSource ss1(plaintext, true,
    //    new CryptoPP::PK_EncryptorFilter(m_rng, e,
    //        new CryptoPP::StringSink(cipher)
    //    ) // PK_EncryptorFilter
    //); // StringSource
    //return cipher;
}

CryptoPP::SecByteBlock Open4_RSA::Encrypt(CryptoPP::RSA::PublicKey pub_key, const std::string msg)
{
    CryptoPP::AutoSeededRandomPool rnd;

    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(pub_key);
    CryptoPP::SecByteBlock plainText(reinterpret_cast<const CryptoPP::byte*>(&msg[-1]), msg.size());


    size_t ecl = encryptor.CiphertextLength(plainText.size());
    assert(ecl != -1);
    CryptoPP::SecByteBlock ciphertext(ecl);
    encryptor.Encrypt(rnd, plainText, plainText.size(), ciphertext);
    return ciphertext;
}

CryptoPP::SecByteBlock Open4_RSA::EncryptFile(CryptoPP::RSA::PublicKey pub_key, const std::string file)
{
    CryptoPP::AutoSeededRandomPool rnd;

    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(pub_key);
    CryptoPP::SecByteBlock plaintext(reinterpret_cast<const CryptoPP::byte*>(&file[-1]), file.size());


    size_t ecl = encryptor.CiphertextLength(plaintext.size());
    assert(ecl != -1);
    CryptoPP::SecByteBlock ciphertext(ecl);
    encryptor.Encrypt(rnd, plaintext, plaintext.size(), ciphertext);
    return ciphertext;
}

std::string Open4_RSA::ConvertToString(CryptoPP::SecByteBlock block)
{
    std::string str;
    str.resize(block.size());
    memcpy(&str[0], &block[0], str.size());
    return str;
}

CryptoPP::SecByteBlock Open4_RSA::ConvertToSecBlock(std::string str)
{
    CryptoPP::SecByteBlock text(reinterpret_cast<const CryptoPP::byte*>(&str[-1]), str.size());
    return text;
}

std::string Open4_RSA::Decrypt(std::string ciphertext)
{
    return Decrypt(ConvertToSecBlock(ciphertext), PrivateKey());
    //// Decrypt
    //size_t plainTextSize = m_PrivateKey.MaxPlaintextLength(cipherTextSize);
    //assert(0 != plainTextSize);
    //assert(cipherTextSize >= plainTextSize);

    //CryptoPP::DecodingResult result = m_PrivateKey.Decrypt(m_rng, (CryptoPP::byte*)cipherText, cipherTextSize, (CryptoPP::byte*)plainText);
    //assert(plainTextSize == result.messageLength);

    //// Decryption
    //CryptoPP::RSAES_OAEP_SHA_Decryptor d(m_PrivateKey);
    //std::string recovered;

    //CryptoPP::StringSource ss2(ciphertext, true,
    //    new CryptoPP::PK_DecryptorFilter(m_rng, d,
    //        new CryptoPP::StringSink(recovered)
    //    ) // PK_DecryptorFilter
    //); // StringSource

    //return recovered;
}

std::string Open4_RSA::Decrypt(CryptoPP::SecByteBlock ciphertext, CryptoPP::RSA::PrivateKey priv_key)
{
    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(priv_key);

    //checks
    assert(0 != decryptor.FixedMaxPlaintextLength());
    assert(ciphertext.size() <= decryptor.FixedCiphertextLength());

    // Create recovered text space
    size_t dpl = decryptor.MaxPlaintextLength(ciphertext.size());
    assert(0 != dpl);
    CryptoPP::SecByteBlock recovered(dpl);

    // Decoding text
    CryptoPP::DecodingResult result = decryptor.Decrypt(rnd,
        ciphertext, ciphertext.size(), recovered);

    // More sanity checks
    assert(result.isValidCoding);
    assert(result.messageLength <= decryptor.MaxPlaintextLength(ciphertext.size()));
    //Resised the buffer to the correct length and converts it to string format
    recovered.resize(result.messageLength);
    std::string message = ConvertToString(recovered);
    return message;
}

std::string Open4_RSA::SignMessage(std::string ciphertext)
{
    // Sign and Encode
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(m_PrivateKey);
    std::string signature;

    CryptoPP::StringSource ss1(ciphertext, true,
        new CryptoPP::SignerFilter(m_rng, signer,
            new CryptoPP::StringSink(signature)
        ) // SignerFilter
    ); // StringSource

    return signature;
}

bool Open4_RSA::Verify(std::string ciphertext, std::string signature)
{
    // Verify and Recover
    CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(m_PublicKey);

    CryptoPP::StringSource ss2(ciphertext + signature, true,
        new CryptoPP::SignatureVerificationFilter(
            verifier, NULL,
            CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION
        ) // SignatureVerificationFilter
    ); // StringSource

    std::cout << "Verified signature on message" << std::endl;
    return false;
}

void Open4_RSA::SaveFile(std::string filename, std::string msg)
{
    std::ofstream encFile(filename);
    encFile << msg;
}

void Open4_RSA::SaveKey(const std::string filename, const CryptoPP::RSA::PublicKey& key)
{
    CryptoPP::ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void Open4_RSA::SaveKey(const std::string filename, const CryptoPP::RSA::PrivateKey& key)
{
    CryptoPP::ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void Open4_RSA::Save(const std::string filename, const CryptoPP::BufferedTransformation& bt)
{
    CryptoPP::FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void Open4_RSA::KeyString(const CryptoPP::RSA::PublicKey key, const std::string inKey)
{
    CryptoPP::ByteQueue queue;
    key.DEREncodePublicKey(queue);
    key.Save(queue);
    std::string temp;
    //CryptoPP::StringSink str(inKey.c_str());
    //queue.CopyTo(inKey);
    //inKey.MessageEnd();
}





#if 0
#include <cryptopp/cryptlib.h>
#include <assert.h>
#include <cryptopp/queue.h>
#include <cryptopp/secblockfwd.h>
#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/secblock.h>
#include <sstream>


void SaveKey(const std::string filename, const CryptoPP::RSA::PublicKey& key);
void SaveKey(const std::string filename, const CryptoPP::RSA::PrivateKey& key);
void Save(const std::string filename, const CryptoPP::BufferedTransformation& bt);
std::string Convert(CryptoPP::SecByteBlock block);
std::string decrypt(CryptoPP::SecByteBlock ciphertext, CryptoPP::RSA::PrivateKey priv_key);
CryptoPP::RSA::PrivateKey createPrivateKey(int size);
CryptoPP::SecByteBlock Encrypt(CryptoPP::RSA::PublicKey pub_key, const std::string file);
std::string read(std::string filename);

int main(int argc, char* argv[]) {
    std::string file = read(argv[1]);
    std::cout << file << "\n";
    //creates a public and private key
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::RSA::PrivateKey priv_key;
    priv_key.GenerateRandomWithKeySize(prng, 3072);


    CryptoPP::RSA::PublicKey pub_key(priv_key);
    SaveKey("priv", priv_key);
    SaveKey("pub", pub_key);

    //Encrypts the file using the public key
    CryptoPP::SecByteBlock ciphertext = Encrypt(pub_key, file);
    //Converts the encrypted data to string format and saves it in a file
    std::string encryptStr = Convert(ciphertext);

    std::ofstream encFile("encrypt.txt");
    encFile << encryptStr;

    std::cout << "Decrypted text " << decrypt(ciphertext, priv_key) << "\n";
    return 0;
}



std::string decrypt(CryptoPP::SecByteBlock ciphertext, CryptoPP::RSA::PrivateKey priv_key) {
    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(priv_key);

    //checks
    assert(0 != decryptor.FixedMaxPlaintextLength());
    assert(ciphertext.size() <= decryptor.FixedCiphertextLength());

    // Create recovered text space
    size_t dpl = decryptor.MaxPlaintextLength(ciphertext.size());
    assert(0 != dpl);
    CryptoPP::SecByteBlock recovered(dpl);

    // Decoding text
    CryptoPP::DecodingResult result = decryptor.Decrypt(rnd,
        ciphertext, ciphertext.size(), recovered);

    // More sanity checks
    assert(result.isValidCoding);
    assert(result.messageLength <= decryptor.MaxPlaintextLength(ciphertext.size()));
    //Resised the buffer to the correct length and converts it to string format
    recovered.resize(result.messageLength);
    std::string message = Convert(recovered);
    return message;
}
void Save(const std::string filename, const CryptoPP::BufferedTransformation& bt) {
    CryptoPP::FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();

}
void SaveKey(const std::string filename, const CryptoPP::RSA::PublicKey& key) {
    CryptoPP::ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);

}
void SaveKey(const std::string filename, const CryptoPP::RSA::PrivateKey& key) {
    CryptoPP::ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

CryptoPP::SecByteBlock Encrypt(CryptoPP::RSA::PublicKey pub_key, const std::string file) {
    CryptoPP::AutoSeededRandomPool rnd;

    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(pub_key);
    CryptoPP::SecByteBlock plaintext(reinterpret_cast<const CryptoPP::byte*>(&file[-1]), file.size());


    size_t ecl = encryptor.CiphertextLength(plaintext.size());
    assert(ecl != -1);
    CryptoPP::SecByteBlock ciphertext(ecl);
    encryptor.Encrypt(rnd, plaintext, plaintext.size(), ciphertext);
    return ciphertext;
}
std::string Convert(CryptoPP::SecByteBlock block) {
    std::string str;
    str.resize(block.size());
    memcpy(&str[0], &block[0], str.size());
    return str;
}
std::string read(std::string filename) {
    std::ifstream file;
    file.open(filename);
    assert(file.is_open());
    std::ostringstream sstr;
    sstr << file.rdbuf();
    return sstr.str();


}

 // Susgested
std::ifstream   file(file);
std::ofstream   encryptedFile(file + ".encryp");
EnctptedStream  encryptedStream(encryptedFile, publicKey);

encryptedStream << file.rdbuf();

 // Make the encryption be a normal stream like object.
 // Then you can send data to the encryption stream just like
 // you send data to a normal stream (so it can be used anywhere
 // you would normally use a stream the using code does not need
 // to know that this is a special stream).
 //
 // I would also make it a wrapper of a stream so we can send the
 // data to any other normla stream be that a file or a memory
 // buffer.
class EnctptedStream : public std::ostream
{
public:
    EnctptedStream(std::ostream& stream, Key key);
};


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>

using namespace CryptoPP;

void rsa_examples()
{
    // Keys created here may be used by OpenSSL.
    //
    // openssl pkcs8 -in key.der -inform DER -out key.pem -nocrypt 
    // openssl rsa -in key.pem -check

    AutoSeededRandomPool rng;

    // Create a private RSA key and write it to a file using DER.
    RSAES_OAEP_SHA_Decryptor priv(rng, 4096);
    TransparentFilter privFile(new FileSink("rsakey.der"));
    priv.DEREncode(privFile);
    privFile.MessageEnd();

    // Create a private RSA key and write it to a string using DER (also write to a file to check it with OpenSSL).
    std::string the_key;
    RSAES_OAEP_SHA_Decryptor pri(rng, 2048);
    TransparentFilter privSink(new StringSink(the_key));
    pri.DEREncode(privSink);
    privSink.MessageEnd();

    std::ofstream file("key.der", std::ios::out | std::ios::binary);
    file.write(the_key.data(), the_key.size());
    file.close();

    // Example Encryption & Decryption
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1536);

    std::string plain = "RSA Encryption", cipher, decrypted_data;

    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);

    RSAES_OAEP_SHA_Encryptor e(publicKey);
    StringSource(plain, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher)));

    RSAES_OAEP_SHA_Decryptor d(privateKey);
    StringSource(cipher, true, new PK_DecryptorFilter(rng, d, new StringSink(decrypted_keydata)));

    assert(plain == decrypted_data);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////
// Generate keys
AutoSeededRandomPool rng;

InvertibleRSAFunction parameters;
parameters.GenerateRandomWithKeySize(rng, 1536);

RSA::PrivateKey privateKey(parameters);
RSA::PublicKey publicKey(parameters);

////////////////////////////////////////////////
// Secret to protect
static const int SECRET_SIZE = 16;
SecByteBlock plaintext(SECRET_SIZE);
memset(plaintext, 'A', SECRET_SIZE);

////////////////////////////////////////////////
// Encrypt
RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

// Now that there is a concrete object, we can validate
assert(0 != encryptor.FixedMaxPlaintextLength());
assert(plaintext.size() <= encryptor.FixedMaxPlaintextLength());

// Create cipher text space
size_t ecl = encryptor.CiphertextLength(plaintext.size());
assert(0 != ecl);
SecByteBlock ciphertext(ecl);

encryptor.Encrypt(rng, plaintext, plaintext.size(), ciphertext);

////////////////////////////////////////////////
// Decrypt
RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

// Now that there is a concrete object, we can check sizes
assert(0 != decryptor.FixedCiphertextLength());
assert(ciphertext.size() <= decryptor.FixedCiphertextLength());

// Create recovered text space
size_t dpl = decryptor.MaxPlaintextLength(ciphertext.size());
assert(0 != dpl);
SecByteBlock recovered(dpl);

DecodingResult result = decryptor.Decrypt(rng,
    ciphertext, ciphertext.size(), recovered);

// More sanity checks
assert(result.isValidCoding);
assert(result.messageLength <= decryptor.MaxPlaintextLength(ciphertext.size()));

// At this point, we can set the size of the recovered
//  data. Until decryption occurs (successfully), we
//  only know its maximum size
recovered.resize(result.messageLength);

// SecByteBlock is overloaded for proper results below
assert(plaintext == recovered);

cout << "Recovered plain text" << endl;

//////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////
// Generate keys
AutoSeededRandomPool rng;

InvertibleRSAFunction params;
params.GenerateRandomWithKeySize(rng, 1536);

RSA::PrivateKey privateKey(params);
RSA::PublicKey publicKey(params);

string plain = "RSA Encryption", cipher, recovered;

////////////////////////////////////////////////
// Encryption
RSAES_OAEP_SHA_Encryptor e(publicKey);

StringSource ss1(plain, true,
    new PK_EncryptorFilter(rng, e,
        new StringSink(cipher)
    ) // PK_EncryptorFilter
); // StringSource

////////////////////////////////////////////////
// Decryption
RSAES_OAEP_SHA_Decryptor d(privateKey);

StringSource ss2(cipher, true,
    new PK_DecryptorFilter(rng, d,
        new StringSink(recovered)
    ) // PK_DecryptorFilter
); // StringSource

assert(plain == recovered);

#endif

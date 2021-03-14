#include <string>
#include <fstream>
#include <iostream>
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <immintrin.h>	// _rdrand32_step
#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include "encryptions.h"
#include "constants.h"

// asymmetric keys functions
void generate_asymmetric_keys(string* private_key, uint8_t* public_key)
{
	// first we generate the private key
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::InvertibleRSAFunction privkey;
	privkey.Initialize(rng, 1024);

	// then we store it with a string sink
	string s_private_key;
	CryptoPP::Base64Encoder privkeysink(new CryptoPP::StringSink(s_private_key));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();
	*private_key = s_private_key;

	// then we create the public key
	CryptoPP::RSAFunction pubkey(privkey);
	string public_key_string;
	CryptoPP::Base64Encoder pubkeysink(new CryptoPP::StringSink(public_key_string));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();

	// then we save the key 
	CryptoPP::ByteQueue bytes;
	CryptoPP::ArraySource pkey(public_key_string, true, new CryptoPP::Base64Decoder);
	pkey.TransferTo(bytes);
	bytes.MessageEnd();
	CryptoPP::RSA::PublicKey pubKey;
	pubKey.Load(bytes);

	CryptoPP::ArraySink as(public_key, PUBLIC_KEY_LENGTH);
	pubKey.Save(as);
}

string asymmetric_encypt(const string& message, uint8_t *public_key)
{
	// first we load the public key
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::ArraySource as(public_key, PUBLIC_KEY_LENGTH, true);
	CryptoPP::RSA::PublicKey pubKey;
	pubKey.Load(as);

	// then we encrypt the message with it
	string ciphertext;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(pubKey);
	CryptoPP::StringSource ss(message, true, new CryptoPP::PK_EncryptorFilter(rng, e, new CryptoPP::StringSink(ciphertext)));

	return ciphertext;
}

string asymmetric_decrypt(const string& cipher_message, string* private_key)
{
	CryptoPP::AutoSeededRandomPool rng;

	// read private key from string
	CryptoPP::ByteQueue bytes;
	CryptoPP::StringSource keystring(*private_key, true, new CryptoPP::Base64Decoder);
	keystring.TransferTo(bytes);
	bytes.MessageEnd();
	CryptoPP::RSA::PrivateKey privKey;
	privKey.Load(bytes);

	// decrypt ciphertext
	string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(privKey);
	CryptoPP::StringSource ss(cipher_message, true, new CryptoPP::PK_DecryptorFilter(rng, d, new CryptoPP::StringSink(decrypted)));

	return decrypted;
}

// symmetric keys functions
char* symmetric_key_generate(char* buff, size_t size)
{
	for (size_t i = 0; i < size; i += 4)
		_rdrand32_step(reinterpret_cast<unsigned int*>(&buff[i]));
	return buff;
}

string encrypt_symmetric(const string& message, const string& symmetric_key)
{
	string ciphertext;
	uint8_t sym_key[SYMMETRIC_KEY_LENGTH];
	uint8_t iv[SYMMETRIC_KEY_LENGTH] = { 0 };

	for (int i = 0; i < SYMMETRIC_KEY_LENGTH; i++)
		sym_key[i] = (uint8_t)symmetric_key[i];
	
	// create cipher text
	CryptoPP::AES::Encryption aesEncryption(sym_key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(message.c_str()), message.length());
	stfEncryptor.MessageEnd();
	return ciphertext;
}

string decrypt_symmetric(const string& cipher_message, const string& symmetric_key)
{
	string decrypted;
	uint8_t sym_key[SYMMETRIC_KEY_LENGTH];
	uint8_t iv[SYMMETRIC_KEY_LENGTH] = { 0 };

	for (int i = 0; i < SYMMETRIC_KEY_LENGTH; i++)
		sym_key[i] = (uint8_t)symmetric_key[i];

	// decrypt
	CryptoPP::AES::Decryption aesDecryption(sym_key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(cipher_message.c_str()), cipher_message.size());
	stfDecryptor.MessageEnd();
	return decrypted;
}

void symmetric_key_create(string *symmetric_key)
{
	CryptoPP::byte sym_key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];

	memset(sym_key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

	symmetric_key_generate(reinterpret_cast<char*>(sym_key), CryptoPP::AES::DEFAULT_KEYLENGTH);
	reinterpret_cast<uint8_t*>(sym_key);
	
	*symmetric_key = "";
	for (int i = 0; i < SYMMETRIC_KEY_LENGTH; i++)
		*symmetric_key += sym_key[i];
}

#include "Arduino.h"
#include "BluetoothSerial.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"

#if !defined(CONFIG_BT_ENABLED) || !defined(CONFIG_BLUEDROID_ENABLED)
#error Bluetooth is not enabled! Please run `make menuconfig` to and enable it
#endif

#define PRINT_RESULT 1
#define NO_PRINT 0

// 2048-bit RSA key pairs
static uint8_t hpPublicKey[] =
	"-----BEGIN PUBLIC KEY-----\n"
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp6yN4qhtwMG0/O3yqULK\n"
	"hmRd/P+/bqySvlQ9xRZy2Jw8WYLTI9ruX7ToEKwmX7nErvOWJEHj7T03i6aeTymr\n"
	"mkX6TF9zyUu2WrETti+8QwlfeF58j2TFpqGtvJiuMVd78XuNdaWpvY0NIaUlDhBb\n"
	"snFkzhTcAERQEqEIIQEi65HE0NPuR7Nm4ErtXHYqftiom4Vdnt7DLKJX8k2iJERW\n"
	"PTi17HC8cfzHPcaN2D4SPmsogYlOkKaG45hJENjjGfghHIz3W1Xqj2yWjvQd/lIp\n"
	"pBBeiYHvkG5IMU+93vP/Gv3OI8DdJIUUrHBuft3BvlCh0daj8+ezYtvTA2M8pG+5\n"
	"kQIDAQAB\n"
	"-----END PUBLIC KEY-----\n";

static uint8_t dPublicKey[] =
	"-----BEGIN PUBLIC KEY-----\n"
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuRkf411wgdkPdUd98but\n"
	"GW3kLj0GMEh0IR6Y4j9hcAuvupwReW/9cBnlkW0JUGVEIJc09/Gek0tKmTQJnXmG\n"
	"bK59lFQ8w2IlkdOC+nas+KDh0oIqv3oOXqsFobARQPf51WMFC2fNIuHF9A7kA4/h\n"
	"nKMphwbqlIlzuh6+W1WfXR7J5LFOA1354JRzAPNnWxY8cn21MaP4pO7H17fEmhIT\n"
	"xYD6VDuD3vR75VkDIiZj5Kj24fD8Q63HHCYFHMuUXkVlWLjCVncr5Wk4YPj2dCO/\n"
	"4BuVy4Xtb6q0mk1TWj7JaJDSktUQlDEPbRRBsNWenbCW8ZMhLEHyX4VHpC+spVLt\n"
	"9QIDAQAB\n"
	"-----END PUBLIC KEY-----\n";

static uint8_t dPrivKey[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC5GR/jXXCB2Q91\n"
	"R33xu60ZbeQuPQYwSHQhHpjiP2FwC6+6nBF5b/1wGeWRbQlQZUQglzT38Z6TS0qZ\n"
	"NAmdeYZsrn2UVDzDYiWR04L6dqz4oOHSgiq/eg5eqwWhsBFA9/nVYwULZ80i4cX0\n"
	"DuQDj+GcoymHBuqUiXO6Hr5bVZ9dHsnksU4DXfnglHMA82dbFjxyfbUxo/ik7sfX\n"
	"t8SaEhPFgPpUO4Pe9HvlWQMiJmPkqPbh8PxDrcccJgUcy5ReRWVYuMJWdyvlaThg\n"
	"+PZ0I7/gG5XLhe1vqrSaTVNaPslokNKS1RCUMQ9tFEGw1Z6dsJbxkyEsQfJfhUek\n"
	"L6ylUu31AgMBAAECggEAWv9CEQoP1JY8pkCWZzAH4neG9UBk+Xm1Nc8QBDJ6mZX1\n"
	"N32gjZ4D74ebt8nuCUsvmgIcNUTg27LpIrZVf8iN0IJcFH7xPHDU3YMpYi7TzItz\n"
	"WYVKtMWxqNLVOu8PHGyMs14xzbCjReHO6rQjXqjulo4UTWCWFJ4aecbBeK94YFN6\n"
	"ieCEPrb3Y61Nbc3lByMsFay/hQY5qoi5Diq4PRiyWHaypjMx4ODN1iMmzumq0SL7\n"
	"Dm9/EX+HCeeDLB8XIxs8e/TWut21E9driyvtg9rhRJqngLMTURwfcnMNYRqhe3Ib\n"
	"JM0g/CE0hjNDkbHon5zjkdskdXP9FzqkcGZ/I7WnhQKBgQDwAKe6o0/T2lLi8Y82\n"
	"fzLAH+T48V0F/EmQ5t/F4VI1TYRr3QO88x9QRd57iCyoDyVorwP0RYgltHtI3Zw4\n"
	"IY/EpSWdH1o+MiLlA8/AalbYQU0toAThwUrfS5QLOg48EHyFwPrUFRlj6BlzK2VJ\n"
	"9nG1zQVTlF3aTixum+5maTIA4wKBgQDFb5gIImEyAl+GW5BAK36E019l8Ilyf2+w\n"
	"LxVlQuqa4cg70vebiZyHQJmdB8GjyME8XRjMteSJIrXf3rUJD5FDjavuJYKNsGDo\n"
	"nBo6ZvOlimseGRjxJCwyukOHa1jjLAxFM1vnEi4oqvAIx2RANH+yykET4i3TN5t7\n"
	"fvym1ALFRwKBgQCctVDPpOLyyZNla6S/SL6yhCDWC4NZ7Sl728QxSLaM51iXtXBD\n"
	"Z9wCZhynPHssIPekKuLCFMSZGgeFxG3EmOVu2QZ+WYJrKgFu19ZHJSgffEQQjnOh\n"
	"lLx2oLrBud6hiYJFM4SUBlLV0S8M7EDu0mPc+UmJEU9Ww8RvVJGNfRKRUQKBgQCe\n"
	"Gb6kxOMQKNZVwPzCZhHqS1kZSITIK0RE0W9Qp0U2wZaWUVn2MzwlEpXwKUXm4dvb\n"
	"erFhPEbFigYaPzy5BL5OWiRTj7X7wEHaAyb9nXN+HFmqwG44q7644G8zAcMsJxms\n"
	"UHRHlUdhSYDthr3ArEmV4mA6i+QmP2FCg23OKfgOAQKBgQCJHUeLhXOp4gSuRaTY\n"
	"CdZ356LeFU+VMyk3BAKhlamPS/33LgbTzUd1NTbuqbDRuKx5OgvkR1Ml3IfIS3dJ\n"
	"UPQ6WkkqrSu2THKps7jsclJ1+aOcDjMkl6SWljPR9+KQfy9ybj0KKFHpKoJqhA0e\n"
	"CCW6eRGCFtEwWJZcsMDSEb4dOQ==\n"
	"-----END PRIVATE KEY-----\n";

static uint8_t encrypted[MBEDTLS_MPI_MAX_SIZE];
static size_t elen = 0;

static uint8_t decrypted[MBEDTLS_MPI_MAX_SIZE];
static size_t dlen = 0;

char outbuf[256];
char inbuf[256];
unsigned char checksum[32];
unsigned char rnd_string[MBEDTLS_ENTROPY_BLOCK_SIZE];

mbedtls_pk_context encrypt_pk;
mbedtls_entropy_context encrypt_entropy;
mbedtls_ctr_drbg_context encrypt_ctr_drbg;

mbedtls_pk_context decrypt_pk;
mbedtls_entropy_context decrypt_entropy;
mbedtls_ctr_drbg_context decrypt_ctr_drbg;

mbedtls_entropy_context gen_entropy;

BluetoothSerial SerialBT;

int ret;

int sendEncryptedMessage(const unsigned char *message, unsigned int len, unsigned int print_result);
int receiveEncryptedMessage(const unsigned char *input, unsigned int in_len, unsigned int print_result);
void exit();
void printBytes(const unsigned char *byte_arr, unsigned int len);
void printError(int errcode);

void setup()
{
	Serial.begin(115200);
	Serial.println("Initializing...");

	mbedtls_pk_init(&encrypt_pk);
	mbedtls_entropy_init(&encrypt_entropy);
	mbedtls_ctr_drbg_init(&encrypt_ctr_drbg);

	mbedtls_pk_init(&decrypt_pk);
	mbedtls_entropy_init(&decrypt_entropy);
	mbedtls_ctr_drbg_init(&decrypt_ctr_drbg);

	mbedtls_entropy_init(&gen_entropy);

	Serial.println("Seeding encrypt_entropy function...");
	ret = mbedtls_ctr_drbg_seed(&encrypt_ctr_drbg, mbedtls_entropy_func, &encrypt_entropy,
								NULL, 0);
	if (ret != 0)
	{
		// Randomizer error
		printError(ret);
		exit();
	}

	Serial.println("Seeding decrypt_entropy function...");
	ret = mbedtls_ctr_drbg_seed(&decrypt_ctr_drbg, mbedtls_entropy_func, &decrypt_entropy,
								NULL, 0);
	if (ret != 0)
	{
		// Randomizer error
		printError(ret);
		exit();
	}

	Serial.println("Loading public RSA key...");
	// Read the public key of user's phone
	if ((ret = mbedtls_pk_parse_public_key(&encrypt_pk, hpPublicKey, sizeof(hpPublicKey))) != 0)
	{
		// public key error
		printError(ret);
		exit();
	}
	Serial.println("Loading RSA private key...");
	if ((ret = mbedtls_pk_parse_key(&decrypt_pk, dPrivKey, sizeof(dPrivKey), NULL, 0)) != 0)
	{
		// public key error
		printError(ret);
		exit();
	}
	SerialBT.begin("ESP32test"); //Bluetooth device name
	Serial.println("The device started, now you can pair it with bluetooth!");
}

void loop()
{
	int res;
	if (Serial.available())
	{
		int to_send = Serial.available();
		Serial.readBytes(outbuf, to_send);
		// check if serial input is a command
		if (outbuf[0] == '>')
		{
			// generate 64-chars random string
			res = mbedtls_entropy_func(&gen_entropy, rnd_string, sizeof(rnd_string));
			if (res != 0) // Error
			{
				printError(res);
			}
			else
			{
				Serial.println("Random string: ");
				printBytes(rnd_string, sizeof(rnd_string));
				char b64_buf[256];
				size_t b64_len;
				// encode in b64 and store it in the buffer
				res = mbedtls_base64_encode((unsigned char *)b64_buf, sizeof(b64_buf), &b64_len,
											rnd_string, sizeof(rnd_string));
				if (res != 0)
				{
					printError(res);
					memcpy(outbuf, rnd_string, sizeof(rnd_string));
					to_send = sizeof(rnd_string);
					mbedtls_sha256(rnd_string, sizeof(rnd_string), checksum, 0);
				}
				else
				{
					Serial.println("In base 64: ");
					Serial.write((unsigned char *)b64_buf, b64_len);
					Serial.println();
					Serial.print(b64_len);
					Serial.print(" characters long.");
					memcpy(outbuf, b64_buf, b64_len);
					to_send = b64_len;
					mbedtls_sha256((const unsigned char *)b64_buf, b64_len, checksum, 0);
				}
				// Print the checksum
				res = mbedtls_base64_encode((unsigned char *)b64_buf, sizeof(b64_buf), &b64_len,
											checksum, sizeof(checksum));
				if (res == 0) 
				{
					Serial.println("The checksum in base 64: ");
					Serial.write((unsigned char *)b64_buf, b64_len);
					Serial.println();
				}
			}
		}
		else if (outbuf[0] == '/')
		{
			// compare the hash with the received message
			int no_mismatch = 1;
			for (int i = 0; i < 32 && no_mismatch; i++)
			{
				no_mismatch = (decrypted[i] == checksum[i]);
			}
			if (no_mismatch)
				Serial.println("Checksum OK");
			else
				Serial.println("Checksum fail");
		}
		else // send user input
		{
			Serial.println("User input:");
		}
		printBytes((const unsigned char *)outbuf, to_send);
		res = sendEncryptedMessage((const unsigned char *)outbuf, to_send, PRINT_RESULT);
	}

	if (SerialBT.available())
	{
		unsigned int to_read = SerialBT.available();
		SerialBT.readBytes(inbuf, to_read);
		Serial.println("Received:");
		printBytes((const unsigned char *)inbuf, to_read);
		res = receiveEncryptedMessage((const unsigned char *)inbuf, to_read, PRINT_RESULT);
	}

	delay(20);
}

int sendEncryptedMessage(const unsigned char *message, unsigned int len, unsigned int print_result)
{
	// Encrypt
	int ret;
	if ((ret = mbedtls_pk_encrypt(&encrypt_pk, message, len,
								  encrypted, &elen, sizeof(encrypted),
								  mbedtls_ctr_drbg_random, &encrypt_ctr_drbg)) != 0)
	{
		printError(ret);
		Serial.print(" Decryption error!");
		return 1;
	}
	else // encrypt ok
	{
		if (print_result == PRINT_RESULT)
		{
			Serial.println("Sending :");
			printBytes(encrypted, elen);
		}
		SerialBT.write(encrypted, elen);
		return 0;
	}
}

int receiveEncryptedMessage(const unsigned char *input, unsigned int in_len, unsigned int print_result)
{
	// Decrypt
	int ret;
	if ((ret = mbedtls_pk_decrypt(&decrypt_pk, input, in_len,
								  decrypted, &dlen, sizeof(decrypted),
								  mbedtls_ctr_drbg_random, &decrypt_ctr_drbg)) != 0)
	{
		// Decryption error
		printError(ret);
		Serial.print(" Decryption error!");
		return 1;
	}
	else // Decryption OK
	{
		if (print_result == PRINT_RESULT)
		{
			Serial.println("Decrypted:");
			Serial.write(decrypted, dlen);
			Serial.println();
			char b64_buf[256];
			size_t b64_len;
			// encode in b64 and store it in the buffer
			ret = mbedtls_base64_encode((unsigned char *)b64_buf, sizeof(b64_buf), &b64_len,
										decrypted, dlen);
			if (ret == 0)
			{
				Serial.println("In base 64: ");
				Serial.write((unsigned char *)b64_buf, b64_len);
			}
			Serial.println();
		}
		return 0;
	}
}

void exit()
{
	mbedtls_pk_free(&encrypt_pk);
	mbedtls_ctr_drbg_free(&encrypt_ctr_drbg);
	mbedtls_entropy_free(&encrypt_entropy);
	while (true)
	{
	}
}

void printBytes(const unsigned char *byte_arr, unsigned int len)
{
	Serial.println("The message in bytes:");
	for (int i = 0; i < len; i++)
	{
		if ((i % 16) == 0)
			Serial.println();
		char str[4];
		sprintf(str, "%02X ", (int)byte_arr[i]);
		Serial.print(str);
	}
	Serial.println();
}

void printError(int errcode)
{
	char buf[256];
	mbedtls_strerror(errcode, buf, sizeof(buf));
	Serial.write((unsigned char *)buf, strlen(buf));
}
#include "Arduino.h"
#include "BluetoothSerial.h"
#include "mbedtls/pk.h"
#include "mbedtls/cipher.h"
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
#define USE_SHA_256 0
#define SHA_256_BYTES 32
#define RSA_MAX_BYTES 256

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

const char symkey[] =
	"abcdefghijklmnop";

static uint8_t encrypted[MBEDTLS_MPI_MAX_SIZE];
static size_t elen = 0;

static uint8_t decrypted[MBEDTLS_MPI_MAX_SIZE];
static size_t dlen = 0;

char outbuf[MBEDTLS_MPI_MAX_SIZE];
unsigned int outbuf_len;

char inbuf[MBEDTLS_MPI_MAX_SIZE];
unsigned int inbuf_len;

unsigned char checksum[SHA_256_BYTES];
unsigned char rnd_string[16];

static unsigned char keybuf[1024];
static unsigned int keylen = 0;

mbedtls_pk_context encrypt_pk;
mbedtls_entropy_context encrypt_entropy;
mbedtls_ctr_drbg_context encrypt_ctr_drbg;

mbedtls_pk_context decrypt_pk;
mbedtls_entropy_context decrypt_entropy;
mbedtls_ctr_drbg_context decrypt_ctr_drbg;

mbedtls_entropy_context gen_entropy;

mbedtls_aes_context aes;
// mbedtls_cipher_context_t cipher_enc;
// mbedtls_cipher_info_t *cipher_enc_info;

// mbedtls_cipher_context_t cipher_dec;
// mbedtls_cipher_info_t *cipher_dec_info;

BluetoothSerial SerialBT;

int sendEncryptedMessage(const unsigned char *message, unsigned int len, unsigned int print_result);
int decryptReceivedMessage(const unsigned char *input, unsigned int in_len, unsigned int print_result);
int generateChallenge();
void exit();
void printBytes(const unsigned char *byte_arr, unsigned int len, const char *header, unsigned int header_len);
void printError(int errcode);
void generateKeyPair();

#define STATE_DEF 0
#define STATE_CHALLENGE 1
#define STATE_VERIFICATION 2
#define STATE_PIN 3
#define STATE_UNLOCK 4
#define STATE_ALARM 5
#define STATE_ERR 6

unsigned int bt_state = STATE_DEF;
const char *USER_ID = "1998";
const char *USER_PIN = "1234";

void fsm()
{
	int out_res = 0;
	int in_res = 0;

	switch (bt_state)
	{
	case STATE_DEF:
	{
		// Send message to user's phone
		if ((outbuf_len = Serial.available()) > 0)
		{
			Serial.readBytes(outbuf, outbuf_len);
			Serial.print("Input pengguna: ");
			Serial.write((const unsigned char *)outbuf, outbuf_len);
			Serial.print(" (");
			Serial.print(outbuf_len);
			Serial.println(")");
			const char *header = "Pesan tak terenkripsi: ";
			printBytes((const unsigned char *)outbuf, outbuf_len, header, strlen(header));
			SerialBT.write((unsigned char *)outbuf, outbuf_len);
		}

		if ((inbuf_len = SerialBT.available()) > 0)
		{
			SerialBT.readBytes(inbuf, inbuf_len);
			Serial.println("Pesan diterima : ");
			Serial.write((const unsigned char *)inbuf, inbuf_len);
			Serial.println();
			printBytes((const unsigned char *)inbuf, inbuf_len, NULL, 0);
			Serial.println();
			// change state depending on user input
			int no_mismatch = 1;
			// check if user ID is registered
			for (int i = 0; i < strlen(USER_ID) && no_mismatch; i++)
			{
				no_mismatch = (USER_ID[i] == inbuf[i]);
			}
			// if found, send ACK and go to next step
			// TODO: Pick a special value for ACK and NACK
			if (no_mismatch)
			{
				outbuf[0] = '1';
				outbuf_len = 1; // ACK
				SerialBT.write((unsigned char *)outbuf, outbuf_len);
				Serial.print("State: Challenge");
				bt_state = STATE_CHALLENGE;
			}
			else // send NACK
			{
				outbuf[0] = '0';
				outbuf_len = 1; // NACK
				SerialBT.write((unsigned char *)outbuf, outbuf_len);
				bt_state = STATE_DEF;
			}
		}
		break;
	}
	case STATE_CHALLENGE:
	{
		out_res = generateChallenge();
		if (out_res != 0) // Challenge generation fail
		{
			bt_state = STATE_ERR;
		}
		else // OK, send challenge w/o encryption
		{
			SerialBT.write((unsigned char *)outbuf, outbuf_len);
			bt_state = STATE_VERIFICATION;
		}
		break;
	}
	case STATE_VERIFICATION:
	{
		if ((inbuf_len = SerialBT.available()) > 0)
		{
			SerialBT.readBytes(inbuf, inbuf_len);
			const char *header = "Pesan diterima: ";
			printBytes((const unsigned char *)inbuf, inbuf_len, header, strlen(header));
			in_res = decryptReceivedMessage((const unsigned char *)inbuf, inbuf_len, PRINT_RESULT);
			if (in_res != 0)
				bt_state = STATE_ERR;
			else
			{
				// compare the decrypted response with user PIN
				int no_mismatch = (dlen == sizeof(rnd_string)); // array length must be the same
				for (int i = 0; i < sizeof(rnd_string) && no_mismatch; i++)
				{
					no_mismatch = (rnd_string[i] == decrypted[i]);
				}
				if (no_mismatch)
				{
					outbuf[0] = '1';
					outbuf_len = 1; // NACK
					SerialBT.write((unsigned char *)outbuf, outbuf_len);
					bt_state = STATE_PIN;
					Serial.println("State: PIN");
				}
				else
				{
					outbuf[0] = '0';
					outbuf_len = 1; // NACK
					SerialBT.write((unsigned char *)outbuf, outbuf_len);
					bt_state = STATE_ALARM;
				}
			}
		}
		break;
	}
	case STATE_PIN:
	{
		SerialBT.readBytes(inbuf, inbuf_len);
		const char *header = "Pesan diterima: ";
		printBytes((const unsigned char *)inbuf, inbuf_len, header, strlen(header));
		in_res = decryptReceivedMessage((const unsigned char *)inbuf, inbuf_len, PRINT_RESULT);
		if (in_res != 0)
			bt_state = STATE_ERR;
		else
		{
			// compare the decrypted response with the original challenge
			int no_mismatch = (strlen((const char*) decrypted) == strlen(USER_PIN)); // array length must be the same
			for (int i = 0; i < strlen(USER_PIN) && no_mismatch; i++)
			{
				no_mismatch = (USER_PIN[i] == decrypted[i]);
			}
			if (no_mismatch)
			{
				outbuf[0] = '1';
				outbuf_len = 1; // ACK
				SerialBT.write((unsigned char *)outbuf, outbuf_len);
				bt_state = STATE_UNLOCK;
				Serial.println("State: UNLOCK");
			}
			else
			{
				outbuf[0] = '0';
				outbuf_len = 1; // NACK
				SerialBT.write((unsigned char *)outbuf, outbuf_len);
				bt_state = STATE_ALARM;
				Serial.println("State : ALARM");
			}
		}
		break;
	}
	case STATE_UNLOCK:
	{
		Serial.println("!!!! DEVICE UNLOCKED !!!!");
		Serial.println("Silahkan tunggu 1 detik...");
		outbuf[0] = '1';
		outbuf_len = 1; // ACK
		SerialBT.write((unsigned char *)outbuf, outbuf_len);
		delay(1000);
		bt_state = STATE_DEF;
		break;
	}
	case STATE_ALARM:
	{
		Serial.println("!!!! ALARM ON !!!!");
		delay(1000);
		bt_state = STATE_DEF;
		break;
	}
	case STATE_ERR:
	{
		Serial.println("ERROR!! : Silahkan restart device anda.");
		exit();
		break;
	}
	default:
		bt_state = STATE_DEF;
	}
}

void setup()
{
	int ret;
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

	Serial.println("Initializing AES Encryption Cipher...");
	mbedtls_aes_init(&aes);
	if ((ret = mbedtls_aes_setkey_enc(&aes, (const unsigned char *)symkey, strlen(symkey) * 8)) != 0)
	{
		printError(ret);
		exit();
	}
	if ((ret = mbedtls_aes_setkey_dec(&aes, (const unsigned char *)symkey, strlen(symkey) * 8)) != 0)
	{
		printError(ret);
		exit();
	}

	bt_state = STATE_DEF;
	SerialBT.begin("ESP32test"); //Bluetooth device name
	Serial.println("The device started, now you can pair it with bluetooth!");
	outbuf[0] = '\0';
	inbuf[0] = '\0';
	// generateKeyPair();
}

void loop()
{
	fsm();
	delay(20);
}

int generateChallenge()
{
	// generate 16-chars random string
	int res = mbedtls_entropy_func(&gen_entropy, rnd_string, sizeof(rnd_string));
	if (res != 0) // Error
	{
		printError(res);
		return 1;
	}
	else // Random string generation successful
	{
		// copy random string to outbuf
		memcpy(outbuf, rnd_string, sizeof(rnd_string));
		outbuf_len = sizeof(rnd_string);
		// print rnd string
		const char *header = "Random string: ";
		printBytes(rnd_string, sizeof(rnd_string), header, strlen(header));
		// compute the hash of rnd string and print it
		mbedtls_sha256(rnd_string, sizeof(rnd_string), checksum, USE_SHA_256);
		const char *hash_header = "Hash dari random string: ";
		printBytes(checksum, sizeof(checksum), hash_header, strlen(hash_header));
		return 0;
	}
}

int sendEncryptedMessage(const unsigned char *message, unsigned int len, unsigned int print_result)
{
	// Encrypt
	char aes_buf[16];
	int ret = 0;
	elen = 0;
	for (int i = 0; i < len && ret == 0; i += 16)
	{
		// copy message to 16-byte block buffer and pad if needed
		unsigned int k = ((len - i) > 16) ? 16 : (unsigned int)(len - i); // number of bytes to be copied to the block buffer
		memcpy(aes_buf, message + i, k);
		if (k != 16) // number of bytes is not multiple of 16, use padding
		{
			for (int j = k; j < 16; j++)
			{
				aes_buf[j] = 0; // pad w/ nulls
			}
		}
		// encrypt the buffer
		ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char *)aes_buf, encrypted + i);
		if (ret != 0)
		{
			printError(ret);
			return 1;
		}
		elen += 16;
	}

	if (print_result == PRINT_RESULT) // Encryption OK
	{
		const char *header = "Mengirim: ";
		printBytes(encrypted, elen, header, strlen(header));
	}
	SerialBT.write(encrypted, elen);
	return 0;
}

int decryptReceivedMessage(const unsigned char *input, unsigned int in_len, unsigned int print_result)
{
	// Decrypt
	char aes_buf[16];
	int ret = 0;
	dlen = 0;
	for (int i = 0; i < in_len && ret == 0; i += 16)
	{
		// copy message to 16-byte block buffer and pad if needed
		unsigned int k = (in_len - i > 16) ? 16 : (unsigned int)(in_len - i); // number of bytes to be copied to the block buffer
		memcpy(aes_buf, input + i, k);
		// shouldn't happen if the encryption process is properly done on the sender
		if (k != 16)
		{ // number of bytes is not multiple of 16, use padding
			for (int j = k; j < 16; j++)
			{
				aes_buf[j] = 0; // pad w/ nulls
			}
		}
		// decrypt the buffer
		ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char *)aes_buf, decrypted + i);
		if (ret != 0)
		{
			printError(ret);
			return 1;
		}
		dlen += 16;
	}

	if (print_result == PRINT_RESULT)
	{
		Serial.println("Pesan terdekripsi:");
		Serial.write(decrypted, dlen);
		printBytes(decrypted, dlen, NULL, 0);
	}
	return 0;
}

void exit()
{
	mbedtls_pk_free(&encrypt_pk);
	mbedtls_ctr_drbg_free(&encrypt_ctr_drbg);
	mbedtls_entropy_free(&encrypt_entropy);
	mbedtls_pk_free(&decrypt_pk);
	mbedtls_ctr_drbg_free(&decrypt_ctr_drbg);
	mbedtls_entropy_free(&decrypt_entropy);
	mbedtls_aes_free(&aes);

	while (true)
	{
	}
}

void printBytes(const unsigned char *byte_arr, unsigned int len, const char *header, unsigned int header_len)
{
	char b64_buf[1024];
	size_t b64_len;
	if (header != NULL)
		Serial.write((const unsigned char *)header, header_len);
	Serial.println();
	Serial.println("Hex:");
	for (int i = 0; i < len; i++)
	{
		if ((i % 16) == 0 && i != 0)
			Serial.println();
		char str[4];
		sprintf(str, "%02X ", (int)byte_arr[i]);
		Serial.print(str);
	}
	Serial.println();
	int res = mbedtls_base64_encode((unsigned char *)b64_buf, sizeof(b64_buf), &b64_len,
									byte_arr, len);
	if (res == 0)
	{
		Serial.println("Base 64: ");
		Serial.write((unsigned char *)b64_buf, b64_len);
		Serial.println();
	}
	Serial.println("---");
}

void printError(int errcode)
{
	char buf[256];
	mbedtls_strerror(errcode, buf, sizeof(buf));
	Serial.write((unsigned char *)buf, strlen(buf));
}

void generateKeyPair()
{
	mbedtls_pk_context gk;
	mbedtls_rsa_context *rsa;
	mbedtls_entropy_context gk_entropy;
	mbedtls_ctr_drbg_context gk_ctr_drbg;
	mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
	mbedtls_pk_init(&gk);
	mbedtls_ctr_drbg_init(&gk_ctr_drbg);
	mbedtls_entropy_init(&gk_entropy);

	// init with sane values. Don't know what it means though.
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&E);
	mbedtls_mpi_init(&DP);
	mbedtls_mpi_init(&DQ);
	mbedtls_mpi_init(&QP);

	int ret = mbedtls_ctr_drbg_seed(&gk_ctr_drbg, mbedtls_entropy_func, &gk_entropy,
									NULL, 0);
	if (ret != 0)
	{
		printError(ret);
		exit();
	}

	Serial.println("Generating RS....");
	ret = mbedtls_pk_setup(&gk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	if (ret != 0)
	{
		printError(ret);
		exit();
	}
	rsa = mbedtls_pk_rsa(gk);
	ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &gk_ctr_drbg, 2048, 65537);
	if (ret != 0)
	{
		printError(ret);
		exit();
	}
	ret = mbedtls_rsa_export(rsa, &N, &P, &Q, &D, &E);
	if (ret != 0)
	{
		printError(ret);
		exit();
	}
	ret = mbedtls_rsa_export_crt(rsa, &DP, &DQ, &QP);
	if (ret != 0)
	{
		printError(ret);
		exit();
	}

	Serial.println("Writing to serial....");
	unsigned char key_buf[2048];
	unsigned int key_len = 0;
	ret = mbedtls_pk_write_key_pem(&gk, key_buf, sizeof(key_buf));
	if (ret != 0)
	{
		printError(ret);
		exit();
	}
	key_len = strlen((char *)key_buf);
	Serial.write(key_buf, key_len);

	ret = mbedtls_pk_write_pubkey_pem(&gk, key_buf, sizeof(key_buf));
	if (ret != 0)
	{
		printError(ret);
		exit();
	}
	key_len = strlen((char *)key_buf);
	Serial.write(key_buf, key_len);

	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&P);
	mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&E);
	mbedtls_mpi_free(&DP);
	mbedtls_mpi_free(&DQ);
	mbedtls_mpi_free(&QP);

	mbedtls_rsa_free(rsa);
	mbedtls_ctr_drbg_free(&gk_ctr_drbg);
	mbedtls_entropy_free(&gk_entropy);
}
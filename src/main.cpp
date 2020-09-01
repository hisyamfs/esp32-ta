#include <Arduino.h>
#include "btFsm.h"
#include "BluetoothSerial.h"
#include "SPIFFS.h"
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

#define LED 2
#define PRINT_RESULT 1
#define NO_PRINT 0
#define USE_SHA_256 0
#define SHA_256_BYTES 32
#define RSA_MAX_BYTES 256
#define MY_AES_BLOCK_SIZE 16 // AES-128

const int DEBUG_MODE = 1;

static uint8_t symkey[MY_AES_BLOCK_SIZE];

mbedtls_aes_context aes;

BluetoothSerial SerialBT;

char USER_ID[MBEDTLS_MPI_MAX_SIZE];
unsigned int id_len = 0;
char USER_PIN[128];
unsigned int pin_len = 0;

void announceStateImp(fsm_state state);
int readBTInputImp(bt_buffer *inbuf);
int readSInputImp(bt_buffer *outbuf);
int generateNonceImp(bt_buffer *nonce);
int sendReplyImp(bt_reply status);
int writeBTImp(bt_buffer *outbuf);
int checkUserIDImp(bt_buffer *id);
int checkUserPINImp(bt_buffer *pin);
int decryptBTImp(bt_buffer *ciphertext, bt_buffer *msg);
int storePINImp(bt_buffer *pin);
int soundAlarmImp();
void setImmobilizerImp(int enable);
int checkEngineOffImp();
void exit();

void setupImmobilizer();
void enableImmobilizer();
void disableImmobilizer();

void printBytes(const unsigned char *byte_arr, unsigned int len, const char *header, unsigned int header_len);
void printError(int errcode);

void setup()
{
	int ret = 0;
	Serial.begin(115200);

	Serial.println("Initializing...");

	if (!SPIFFS.begin(true))
	{
		Serial.println("An Error has occurred while mounting SPIFFS");
		exit();
	}

	File file = SPIFFS.open("/userPin.txt", FILE_READ);
	if (!file) // Error, credential not found
	{
		Serial.println("Error loading user credential...");
		exit();
	}
	// Cred loading OK
	pin_len = file.available();
	file.readBytes(USER_PIN, pin_len);
	pin_len = strlen((const char *)USER_PIN);
	file.close();

	file = SPIFFS.open("/userKey.txt", FILE_READ);
	if (!file) // Error, credential not found
	{
		Serial.println("Error loading user credential...");
		exit();
	}
	int key_len = file.available();
	file.readBytes((char *)symkey, key_len);
	file.close();

	file = SPIFFS.open("/userId.txt", FILE_READ);
	if (!file) // Error, credential not found
	{
		Serial.println("Error loading user credential...");
		exit();
	}
	id_len = file.available();
	file.readBytes(USER_ID, id_len);
	file.close();

	Serial.println("Stored ID: ");
	Serial.write((const unsigned char *)USER_ID, id_len);
	Serial.println();

	Serial.println("Stored PIN: ");
	Serial.write((const unsigned char *)USER_PIN, pin_len);
	Serial.println();

	Serial.println("Stored Key: ");
	Serial.write((const unsigned char *)symkey, MY_AES_BLOCK_SIZE);
	printBytes((const unsigned char *)symkey, MY_AES_BLOCK_SIZE, NULL, 0);
	Serial.println();

	Serial.println("Initializing AES Encryption Cipher...");
	mbedtls_aes_init(&aes);
	if ((ret = mbedtls_aes_setkey_enc(&aes, (const unsigned char *)symkey, MY_AES_BLOCK_SIZE * 8)) != 0)
	{
		printError(ret);
		exit();
	}
	if ((ret = mbedtls_aes_setkey_dec(&aes, (const unsigned char *)symkey, MY_AES_BLOCK_SIZE * 8)) != 0)
	{
		printError(ret);
		exit();
	}

	Serial.println("Initializing state machine....");
	ret = init_btFsm(
		&announceStateImp,
		&readBTInputImp,
		&readSInputImp,
		&generateNonceImp,
		&sendReplyImp,
		&writeBTImp,
		&checkUserIDImp,
		&checkUserPINImp,
		&decryptBTImp,
		&storePINImp,
		&soundAlarmImp,
		&setImmobilizerImp,
		&checkEngineOffImp,
		&exit);
	if (ret != BT_SUCCESS)
	{
		Serial.println("State machine init failed.");
		while (1) {};
	}

	Serial.println("Initializing immobilizer....");
	setupImmobilizer();
	setImmobilizerImp(BT_ENABLE);

	SerialBT.begin("ESP32test"); //Bluetooth device name
	Serial.println("The device started, now you can pair it with bluetooth!");
}

void loop()
{
	// int lc = 0;
	// for (lc = 0; lc < 50; lc++)
	// {
	run_btFsm();
	delay(20);
	// Serial.println("Loop!");
	// }
	// Serial.println("loop");
}

void announceStateImp(fsm_state state)
{
	switch (state)
	{
	case STATE_ERR:
		Serial.println("STATE : ERR");
		break;
	case STATE_DEF:
		Serial.println("STATE : DEF");
		break;
	case STATE_ID_CHECK:
		Serial.println("STATE : ID CHECK");
		break;
	case STATE_CHALLENGE:
		Serial.println("STATE : CHALLENGE");
		break;
	case STATE_VERIFICATION:
		Serial.println("STATE : VERIFICATION");
		break;
	case STATE_PIN:
		Serial.println("STATE : PIN");
		break;
	case STATE_UNLOCK:
		Serial.println("STATE : UNLOCK");
		break;
	case STATE_NEW_PIN:
		Serial.println("STATE : NEW PIN");
		break;
	case STATE_ALARM:
		Serial.println("STATE : ALARM");
		break;
	case STATE_KEY_EXCHANGE:
		Serial.println("STATE : KEY EXCHANGE");
		break;
	case STATE_REGISTER:
		Serial.println("STATE : REGISTER");
		break;
	default:
		Serial.println("UNDEFINED STATE");
	}
}

int readBTInputImp(bt_buffer *inbuf)
{
	int incoming = SerialBT.available();
	if (incoming)
	{
		if (incoming > BT_BUF_LEN_BYTE)
			incoming = BT_BUF_LEN_BYTE; // clamp inbuf length
		inbuf->len = incoming;
		SerialBT.readBytes(inbuf->data, inbuf->len);
		if (DEBUG_MODE)
		{
			Serial.println("HP: ");
			Serial.write(inbuf->data, inbuf->len);
			Serial.println();
			printBytes(inbuf->data, inbuf->len, NULL, 0);
		}
		return inbuf->len;
	}
	else // No incoming data
		return 0;
}

int readSInputImp(bt_buffer *outbuf)
{
	int incoming = Serial.available();
	if (incoming)
	{
		if (incoming > BT_BUF_LEN_BYTE)
			incoming = BT_BUF_LEN_BYTE; // clamp inbuf length
		outbuf->len = incoming;
		Serial.readBytes(outbuf->data, outbuf->len);
		if (DEBUG_MODE)
		{
			Serial.println("ESP32: ");
			Serial.write(outbuf->data, outbuf->len);
			Serial.println();
			printBytes(outbuf->data, outbuf->len, NULL, 0);
		}
		return outbuf->len;
	}
	else // No incoming data
		return 0;
}

// TODO("Ganti agar menggunakan CTR-DRBG")
int generateNonceImp(bt_buffer *nonce)
{
	mbedtls_entropy_context key_gen_entropy;
	mbedtls_entropy_init(&key_gen_entropy);
	// generate 16-chars random string
	unsigned char nonce_buf[BT_BLOCK_SIZE_BYTE];
	int res = mbedtls_entropy_func(&key_gen_entropy, nonce_buf, BT_BLOCK_SIZE_BYTE);
	if (res != 0) // Error
	{
		printError(res);
		return BT_FAIL;
	}
	else // Random string generation successful
	{
		// fill the nonce with the generated string
		memcpy(nonce->data, nonce_buf, BT_BLOCK_SIZE_BYTE);
		nonce->len = BT_BLOCK_SIZE_BYTE;
		const char *header = "Nonce: ";
		printBytes(nonce->data, nonce->len, header, strlen(header));
		return BT_SUCCESS;
	}
}

int sendReplyImp(bt_reply status)
{
	bt_buffer repl;
	init_bt_buffer(&repl);
	repl.len = 1;
	repl.data[0] = (unsigned char)status;
	return writeBTImp(&repl);
}

int writeBTImp(bt_buffer *outbuf)
{
	SerialBT.write(outbuf->data, outbuf->len);
	if (DEBUG_MODE)
	{
		Serial.println("ESP32: ");
		Serial.write(outbuf->data, outbuf->len);
		Serial.println();
		printBytes(outbuf->data, outbuf->len, NULL, 0);
	}
	return BT_SUCCESS;
}

int checkUserIDImp(bt_buffer *id)
{
	int no_mismatch = (id->len == id_len);
	for (int i = 0; i < BT_BLOCK_SIZE_BYTE && no_mismatch; i++)
	{
		no_mismatch = (id->data[i] == USER_ID[i]);
	}
	if (no_mismatch)
		return BT_SUCCESS;
	else
		return BT_FAIL;
}

int checkUserPINImp(bt_buffer *pin)
{
	int no_mismatch = (strlen((const char *)pin->data) == pin_len);
	for (int i = 0; i < BT_BLOCK_SIZE_BYTE && no_mismatch; i++)
	{
		no_mismatch = (pin->data[i] == USER_PIN[i]);
	}
	if (no_mismatch)
		return BT_SUCCESS;
	else
		return BT_FAIL;
}

int decryptBTImp(bt_buffer *ciphertext, bt_buffer *msg)
{
	// TODO("Add boundary checking")
	// Decrypt
	char aes_buf[16];
	int ret = 0, in_len = ciphertext->len;
	init_bt_buffer(msg); // clear the output data and set its length to 0
	for (int i = 0; i < in_len && ret == 0 && i < BT_BUF_LEN_BYTE; i += 16)
	{
		// copy message to 16-byte block buffer and pad if needed
		unsigned int k = (in_len - i > 16) ? 16 : (unsigned int)(in_len - i); // number of bytes to be copied to the block buffer
		memcpy(aes_buf, ciphertext->data + i, k);							  // copy data to decryption buffer
		// shouldn't happen if the encryption process is properly done on the sender
		if (k != 16)
		{ // number of bytes is not multiple of 16, use padding
			for (int j = k; j < 16; j++)
			{
				aes_buf[j] = 0; // pad w/ nulls
			}
		}
		// decrypt the buffer
		ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char *)aes_buf, msg->data + i);
		if (ret != 0)
		{
			printError(ret);
			return BT_FAIL;
		}
		msg->len += 16;
	}
	// msg->len = strlen((const char*) msg->data);
	if (DEBUG_MODE)
	{
		Serial.println("Pesan terdekripsi:");
		Serial.write(msg->data, msg->len);
		printBytes(msg->data, msg->len, NULL, 0);
	}
	return BT_SUCCESS;
}

int storePINImp(bt_buffer *pin)
{
	// load the new pin to SPIFFS
	File file = SPIFFS.open("/userPin.txt", FILE_WRITE);
	unsigned int new_pin_len = strlen((const char *)pin->data);
	if (!file)
	{
		Serial.println("Gagal mengubah PIN, silakan coba lagi.");
		return BT_FAIL;
	}
	else if (new_pin_len <= BT_BLOCK_SIZE_BYTE)
	{
		Serial.println("Berhasil mengubah PIN");
		memcpy(USER_PIN, pin->data, new_pin_len);
		pin_len = new_pin_len;
		file.write((const uint8_t *)USER_PIN, pin_len);
		if (DEBUG_MODE)
		{
			Serial.print("PIN Baru : ");
			Serial.println(pin_len);
			Serial.write((const uint8_t *)USER_PIN, pin_len);
			Serial.println();
		}
		return BT_SUCCESS;
	}
	else
	{
		Serial.println("PIN terlalu panjang, harus kurang dari 16 karakter.");
		return BT_FAIL;
	}
	file.close();
}

int soundAlarmImp()
{
	delay(3000);
	return BT_SUCCESS;
}

void setImmobilizerImp(int enable)
{
	if (enable == BT_ENABLE)
		enableImmobilizer();
	else
		disableImmobilizer();
}

int checkEngineOffImp()
{
	delay(3000);
	return BT_SUCCESS;
}

void exit()
{
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

void disableImmobilizer()
{
	digitalWrite(LED, HIGH);
}

void enableImmobilizer()
{
	digitalWrite(LED, LOW);
}

void setupImmobilizer()
{
	pinMode(LED, OUTPUT);
}

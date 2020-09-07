#include <Arduino.h>
#include "btFsm.h"
#include "myBluetoothSerial.h"
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
#define DEBUG_MODE 1

static uint8_t symkey[MY_AES_BLOCK_SIZE];
mbedtls_aes_context aes;
myBluetoothSerial SerialBT;

// char USER_ID[MBEDTLS_MPI_MAX_SIZE];
// unsigned int id_len = 0;
// char USER_PIN[128];
// unsigned int pin_len = 0;

void announceStateImp(fsm_state state);
int generateNonceImp(bt_buffer *nonce);
int sendReplyImp(bt_reply status);
int writeBTImp(const bt_buffer *outbuf);
int decryptBTImp(const bt_buffer *ciphertext, bt_buffer *msg);
int storePINImp(bt_buffer *pin);
int deleteStoredCredImp(void);
int setAlarmImp(int enable, int duration);
int unpairBlacklistImp(const bt_buffer *client);
void setImmobilizerImp(int enable);
void exit(void);

void setupImmobilizer();
void enableImmobilizer();
void disableImmobilizer();

void printBytes(const unsigned char *byte_arr, unsigned int len, const char *header, unsigned int header_len);
void printError(int errcode);
void onBTInputInterface(const uint8_t *buffer, size_t blen);
void custom_callback(esp_spp_cb_event_t event, esp_spp_cb_param_t *param);

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
	size_t pin_len = 0;
	if (!file) // Error, credential not found
	{
		Serial.println("Error loading user credential...");
		// exit();
	}
	// Cred loading OK
	pin_len = file.available();
	char upinbuf[32];
	file.readBytes(upinbuf, pin_len);
	pin_len = strlen((const char *)upinbuf);
	file.close();

	file = SPIFFS.open("/userKey.txt", FILE_READ);
	if (!file) // Error, credential not found
	{
		Serial.println("Error loading user credential...");
		exit();
	}
	size_t key_len = file.available();
	file.readBytes((char *)symkey, key_len);
	file.close();

	file = SPIFFS.open("/userId.txt", FILE_READ);
	size_t id_len = 0;
	if (!file) // Error, credential not found
	{
		Serial.println("Error loading user credential...");
		// exit();
	}
	id_len = file.available();
	char uidbuf[32];
	file.readBytes(uidbuf, id_len);
	file.close();

	Serial.println("Stored ID: ");
	Serial.write((const unsigned char *)uidbuf, id_len);
	Serial.println();

	Serial.println("Stored PIN: ");
	Serial.write((const unsigned char *)upinbuf, pin_len);
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

	Serial.println("Loading credentials....");
	ret = load_user_cred((const uint8_t *)upinbuf, pin_len, (const uint8_t *)uidbuf, id_len);
	if (ret == BT_SUCCESS)
		Serial.println("Registered device : 1");
	else
		Serial.println("No registered device found");

	Serial.println("Initializing immobilizer....");
	setupImmobilizer();
	setImmobilizerImp(BT_ENABLE);

	Serial.println("Initializing state machine....");
	ret = init_btFsm(announceStateImp,
					 generateNonceImp,
					 sendReplyImp,
					 writeBTImp,
					 decryptBTImp,
					 storePINImp,
					 deleteStoredCredImp,
					 setAlarmImp,
					 unpairBlacklistImp,
					 setImmobilizerImp,
					 exit);
	if (ret != BT_SUCCESS)
	{
		Serial.println("State machine init failed.");
		while (1)
		{
		};
	}

	SerialBT.begin("ESP32test"); //Bluetooth device name
	SerialBT.onData(onBTInputInterface);
	esp_err_t cb_ret = SerialBT.register_callback(custom_callback);
	if (cb_ret != ESP_OK)
		Serial.println("Custom callback init failed!");
}

void loop()
{
	size_t slen = Serial.available();
	if (slen > 0 && slen <= 32)
	{
		char sbuf[32];
		Serial.readBytes(sbuf, slen);
		onSInput((const uint8_t *)sbuf, slen);
	}
	delay(20);
}

void custom_callback(esp_spp_cb_event_t event, esp_spp_cb_param_t *param)
{
	static uint8_t cl_addr[6];
	size_t ADDR_LEN = 6;
	switch (event)
	{
	case ESP_SPP_SRV_OPEN_EVT:
	{
		Serial.print("Connected to:");
		Serial.write(param->srv_open.rem_bda, ADDR_LEN);
		Serial.println();
		memcpy(cl_addr, param->srv_open.rem_bda, ADDR_LEN);
		const char header[] = "Client address:";
		printBytes((const uint8_t *)cl_addr, ADDR_LEN, header, strlen(header));
		onBTConnect((const uint8_t *)cl_addr, ADDR_LEN);
		break;
	}
	case ESP_SPP_CLOSE_EVT:
	{
		Serial.println("Disconnected!");
		onBTDisconnect((const uint8_t *)cl_addr, ADDR_LEN);
		break;
	}
	default:
		break;
	}
}

void announceStateImp(fsm_state state)
{
	switch (state)
	{
	case STATE_ERR:
		Serial.println("STATE : ERR");
		break;
	case STATE_DISCONNECT:
		Serial.println("STATE : DISCONNECT");
		break;
	case STATE_CONNECT:
		Serial.println("STATE : CONNECT");
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

int writeBTImp(const bt_buffer *outbuf)
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

int decryptBTImp(const bt_buffer *ciphertext, bt_buffer *msg)
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

// Uses strlen to determine pin's real length, if the param uses padding. Pin's length may be modified by the function
int storePINImp(bt_buffer *pin)
{
	// load the new pin to SPIFFS
	File file = SPIFFS.open("/userPin.txt", FILE_WRITE);
	unsigned int new_pin_len = strlen((const char *)pin->data);
	if (!file)
	{
		Serial.println("Gagal mengubah PIN, silakan coba lagi.");
		file.close();
		return BT_FAIL;
	}
	else if (new_pin_len <= BT_BLOCK_SIZE_BYTE)
	{
		Serial.println("Berhasil mengubah PIN");
		// memcpy(USER_PIN, pin->data, new_pin_len);
		pin->len = new_pin_len;
		file.write((const uint8_t *)pin->data, pin->len);
		if (DEBUG_MODE)
		{
			Serial.print("PIN Baru : ");
			Serial.println(pin->len);
			Serial.write((const uint8_t *)pin->data, pin->len);
			Serial.println();
		}
		file.close();
		return BT_SUCCESS;
	}
	else
	{
		Serial.println("PIN terlalu panjang, harus kurang dari 16 karakter.");
		file.close();
		return BT_FAIL;
	}
}

int deleteStoredCredImp(void)
{
	SPIFFS.remove("/userPin.txt");
	SPIFFS.remove("/userID.ini");
	return BT_SUCCESS;
}

int setAlarmImp(int enable, int duration)
{
	if (enable == BT_ENABLE)
	{
		delay(duration);
		onTimeout();
	}
	return BT_SUCCESS;
}

int unpairBlacklistImp(const bt_buffer *client)
{
	if (client->len == BT_ADDR_LEN)
	{
		SerialBT.unpairDevice((uint8_t *)client->data);
		SerialBT.disconnect();
		return BT_SUCCESS;
	}
	else
		return BT_FAIL;
}

void setImmobilizerImp(int enable)
{
	if (enable == BT_ENABLE)
		enableImmobilizer();
	else
		disableImmobilizer();
}

void exit(void)
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

void onBTInputInterface(const uint8_t *buffer, size_t blen)
{
	if (DEBUG_MODE)
	{
		Serial.println("HP: ");
		Serial.write(buffer, blen);
		Serial.println();
		printBytes(buffer, blen, NULL, 0);
	}
	onBTInput(buffer, blen);
}
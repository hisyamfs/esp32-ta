/**
 * @file coba.cpp
 * @author Siapa ya
 * @brief Versi coba coba: fsm dengan event queue
 */

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
#include "freertos/timers.h"
#include "Ticker.h"
#include "esp_spp_api.h"

#if !defined(CONFIG_BT_ENABLED) || !defined(CONFIG_BLUEDROID_ENABLED)
#error Bluetooth is not enabled! Please run `make menuconfig` to and enable it
#endif

#define CURRENT_COIL 32
#define CURRENT_CONTACT_KEY 34
#define RELAY 26
#define BUZZER 14
#define LED 2
#define ENGINE 4
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

mbedtls_pk_context encrypt_pk;
mbedtls_entropy_context encrypt_entropy;
mbedtls_ctr_drbg_context encrypt_ctr_drbg;

Ticker alarm_ticker, timeout_ticker;

void announceStateImp(fsm_state state);
int generateNonceImp(bt_buffer *nonce);
int sendReplyImp(bt_reply status);
int writeBTImp(const bt_buffer *outbuf);
int decryptBTImp(const bt_buffer *ciphertext, bt_buffer *msg);
int storeCredentialImp(bt_buffer *pin, bt_buffer *client);
int deleteStoredCredImp(void);
int loadPKImp(uint8_t *keybuf, size_t keylen); // Load RSA Pubkey for the RSA Cipher
int setCipherkeyImp(const bt_buffer *nonce);   // Load AES Symkey for the AES-128 Cipher
int writeBTRSAImp(const bt_buffer *out);
int setAlarmImp(int enable, int duration);
int setTimeoutImp(int enable, int duration);
int unpairBlacklistImp(const bt_buffer *client);
void setImmobilizerImp(int enable);
void exit(void);
void disconnectImp();
int setDiscoverabilityImp(int enable);
int customTransitionImp();

fsm_interface m_interface = {
	.announceStateImp = announceStateImp,
	.generateNonceImp = generateNonceImp,
	.sendReplyImp = sendReplyImp,
	.writeBTImp = writeBTImp,
	.decryptBTImp = decryptBTImp,
	.storeCredentialImp = storeCredentialImp,
	.deleteStoredCredentialImp = deleteStoredCredImp,
	.loadPKImp = loadPKImp,
	.setCipherkeyImp = setCipherkeyImp,
	.writeBTRSAImp = writeBTRSAImp,
	.setAlarmImp = setAlarmImp,
	.setTimeoutImp = setTimeoutImp,
	.unpairBlacklistImp = unpairBlacklistImp,
	.setImmobilizerImp = setImmobilizerImp,
	.handleErrorImp = exit,
	.disconnectImp = disconnectImp,
	.setDiscoverabilityImp = setDiscoverabilityImp,
	.customTransitionImp = customTransitionImp};

void setupKeyInput();
void readKeyInput();
void readCurrent();
void displayMeasurement();
void checkBypass();
void setupImmobilizer();
void enableImmobilizer();
void disableImmobilizer();

void printBytes(const unsigned char *byte_arr, unsigned int len, const char *header, unsigned int header_len);
void printError(int errcode);
void onBTInputInterface(const uint8_t *buffer, size_t blen);
void custom_callback(esp_spp_cb_event_t event, esp_spp_cb_param_t *param);

int Voltage1;
int Voltage2;
int Current1;
int Current2;

TaskHandle_t Task1;
TaskHandle_t Task2;
xQueueHandle qFsmEvent;

// Task 1 = baca sensor arus (continous, high priority)
void Task1code(void *pvParameters)
{
	for (;;)
	{
		readCurrent();
		displayMeasurement();
		checkBypass();
	}
}

//Task 2 = baca input serial
void Task2code(void *pvParameters)
{
	static bt_buffer serial;
	for (;;)
	{
		size_t slen = Serial.available();
		if (slen > 0 && slen <= 32)
		{
			char sbuf[32];
			Serial.readBytes(sbuf, slen);
			// onSInput((const uint8_t *)sbuf, slen);
			if (raise_event(&serial, EVENT_S_INPUT, (const uint8_t *)sbuf, slen) == BT_SUCCESS)
				xQueueSend(qFsmEvent, &serial, 0);
		}
		// readKeyInput();
		delay(20);
	}
}

void vTaskFSM(void *pvParameters)
{
	bt_buffer input;
	int ret;
	while (1)
	{
		if (qFsmEvent != NULL && xQueueReceive(qFsmEvent, &input, 0) == pdPASS)
		{
			ret = onInput(&input);
			vTaskDelay(pdMS_TO_TICKS(20));
		}
	}
}

int customTransitionImp(void)
{
	bt_buffer trans;
	trans.event = EVENT_TRANSITION;
	trans.len = 0;
	xQueueSend(qFsmEvent, &trans, 0);
	return BT_SUCCESS;
}

void readCurrent(void)
{
	for (int i = 0; i < 1000; i++)
	{
		//Read current as voltage on GPIO
		Voltage1 = (Voltage1 + ((3.3 / 4095) * abs(analogRead(CURRENT_COIL))));		   // (5 V / 1024 (Analog) = 0.0049) which converter Measured analog input voltage to 5 V Range
		Voltage2 = (Voltage2 + ((3.3 / 4095) * abs(analogRead(CURRENT_CONTACT_KEY)))); // (5 V / 1024 (Analog) = 0.0049) which converter Measured analog input voltage to 5 V Range
		delay(1);
	}

	// Removing bias from sensor measurement
	Voltage1 = (Voltage1 / 1000) - 2.055;
	Voltage2 = (Voltage2 / 1000) - 2.058;

	// Sensed voltage is converter to current (using sensitivity)
	Current1 = (Voltage1) / 0.1;
	Current2 = (Voltage2) / 0.1;
}

void displayMeasurement(void)
{
	Serial.print(Voltage1, 3);
	Serial.print("V  ");
	Serial.print(Current1, 3); // the �2� after voltage allows you to display 2 digits after decimal point
	Serial.print("A      ");
	Serial.print(Voltage2, 3);
	Serial.print("V  ");
	Serial.print(Current2, 3); // the �2� after voltage allows you to display 2 digits after decimal point
	Serial.print("A   ");
}

void checkBypass(void)
{
	bt_buffer engine;
	//Current1 = Current from ECU
	//Current2 = Current from Contact Key
	if (3 * Current1 < Current2)
	{
		digitalWrite(BUZZER, HIGH);
		Serial.println("AWAS, TERJADI BYPASS");
		// SerialBT.disconnect();

		/** Uncomment kalo mau coba pake event di bawah, tapi belum pernah dicoba */
		// const uint8_t is_bypassed = BT_ENABLE;
		// if (raise_event(&engine, EVENT_BYPASS_DETECTOR, &is_bypassed, 1) == BT_SUCCESS)
		// 	xQueueSend(qFsmEvent, &engine, 0);
	}
	else
	{
		if (Current1 < 0, 05)
		{
			digitalWrite(BUZZER, LOW);
			Serial.println("Mesin Mati");
			// onEngineEvent(BT_DISABLE);

			uint8_t off_key = BT_DISABLE;
			if (raise_event(&engine, EVENT_ENGINE, &off_key, 1) == BT_SUCCESS)
				xQueueSend(qFsmEvent, &engine, 0);
		}
		else
		{
			digitalWrite(BUZZER, LOW);
			// Serial.println("Aman");
		}
	}
	delay(10);
}

// Baca posisi kunci motor pengguna -Ini udh ga perlu lagi keknya (Abel)
void setupKeyInput()
{
	pinMode(ENGINE, INPUT_PULLUP);
}

//Ini juga dah gaperlu lagi keknya soalnya udh masuk di void readCurrent (Abel)
void readKeyInput()
{
	// // TODO("Ganti dengan interrupt")
	// static int prev_val = HIGH;
	// int current_val;
	// current_val = digitalRead(ENGINE);
	// if (current_val != prev_val)
	// {
	// 	// onEngineEvent(current_val);
	// 	prev_val = current_val;
	// }
}

void setup()
{
	qFsmEvent = xQueueCreate(20, sizeof(bt_buffer)); // 20 events-long fsm input queue
	int ret = 0;
	Serial.begin(115200);

	Serial.println("Initializing immobilizer....");
	setupImmobilizer();
	setImmobilizerImp(BT_ENABLE);
	setupKeyInput();

	Serial.println("Initializing state machine....");
	ret = init_btFsm(&m_interface);
	if (ret != BT_SUCCESS)
	{
		Serial.println("State machine init failed.");
		while (1)
		{
		};
	}

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
		// exit();
		const char *default_key = "abcdefghijklmnop";
		memcpy(symkey, default_key, BT_BLOCK_SIZE_BYTE);
	}
	size_t key_len = file.available();
	file.readBytes((char *)symkey, key_len);
	file.close();

	file = SPIFFS.open("/userID.ini", FILE_READ);
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
	printBytes((const uint8_t *)uidbuf, id_len, NULL, 0);

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
	{
		Serial.printf("is_registered : %c\n", get_registration_status());
	}
	else
		Serial.println("No registered device found");

	SerialBT.onData(onBTInputInterface);
	esp_err_t cb_ret = SerialBT.register_callback(custom_callback);
	if (cb_ret != ESP_OK)
	{
		Serial.println("Custom callback init failed!");
		exit();
	}
	else
	{
		// uint8_t mac[6];
		// if (esp_efuse_mac_get_default(mac) != ESP_OK)
		// 	SerialBT.begin("ImmobilizerITB-01");
		// else
		// {
		// 	// Use MAC address as unique Immobilizer ID to advertise the connection
		// 	String id = "ImmobilizerITB-";
		// 	for (int i = 0; i < 6; i++)
		// 		id.concat(String(mac[i], HEX));
		// 	SerialBT.begin(id, false, false);
		// }
		Serial.println("---------START----------");
		onTransition();
	}

	// TODO: Handle event congestion
	xTaskCreatePinnedToCore(Task1code, "Task1", 20000, NULL, 1, NULL, 1);
	xTaskCreatePinnedToCore(Task2code, "Task2", 20000, NULL, 1, NULL, 0);
	xTaskCreatePinnedToCore(vTaskFSM, "FSM", 20000, NULL, 1, NULL, 1);
	// Test
	// SerialBT.setDiscoverability(false);
}

void loop()
{
	// size_t slen = Serial.available();
	// if (slen > 0 && slen <= 32)
	// {
	// 	char sbuf[32];
	// 	Serial.readBytes(sbuf, slen);
	// 	onSInput((const uint8_t *)sbuf, slen);
	// }
	// readKeyInput();
	// delay(20);
}

void custom_callback(esp_spp_cb_event_t event, esp_spp_cb_param_t *param)
{
	static uint8_t cl_addr[6];
	static bt_buffer connect_buf;
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
		// onBTConnect((const uint8_t *)cl_addr, ADDR_LEN);
		if (raise_event(&connect_buf, EVENT_BT_CONNECT, (const uint8_t *)cl_addr, ADDR_LEN) == BT_SUCCESS)
			xQueueSend(qFsmEvent, &connect_buf, 0);
		break;
	}
	case ESP_SPP_CLOSE_EVT:
	{
		Serial.println("Disconnected!");
		// onBTDisconnect((const uint8_t *)cl_addr, ADDR_LEN);
		if (raise_event(&connect_buf, EVENT_BT_DISCONNECT, (const uint8_t *)cl_addr, ADDR_LEN) == BT_SUCCESS)
			xQueueSend(qFsmEvent, &connect_buf, 0);
		break;
	}
	default:
		break;
	}
}

void announceStateImp(fsm_state state)
{
	char *state_name[BT_NUM_STATES] =
		{"STATE_ERR",
		 "STATE_DISCONNECT",
		 "STATE_CONNECT",
		 "STATE_CHALLENGE",
		 "STATE_VERIFICATION",
		 "STATE_PIN",
		 "STATE_UNLOCK",
		 "STATE_NEW_PIN",
		 "STATE_DELETE",
		 "STATE_ALARM",
		 "STATE_KEY_EXCHANGE",
		 "STATE_REGISTER",
		 "STATE_UNLOCK_DISCONNECT"};
	Serial.printf("%s\n", state_name[(uint)state % BT_NUM_STATES]);
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
int storeCredentialImp(bt_buffer *pin, bt_buffer *client)
{
	// load the new pin to SPIFFS
	uint success;
	File file = SPIFFS.open("/userPin.txt", FILE_WRITE);
	{
		success = 0;
		unsigned int new_pin_len = strlen((const char *)pin->data);
		if (!file)
			Serial.println("Gagal mengubah PIN, silakan coba lagi.");
		else if (new_pin_len > BT_BLOCK_SIZE_BYTE)
			Serial.println("PIN terlalu panjang, harus kurang dari 16 karakter.");
		else
		{
			success = 1;
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
		}
	}
	file.close();
	if (!success)
		return BT_FAIL;

	// store the client address at SPIFFS
	file = SPIFFS.open("/userID.ini", FILE_WRITE);
	{
		success = 0;
		if (!file)
			Serial.println("Gagal mengubah PIN, silakan coba lagi.");
		else if (client->len != BT_ADDR_LEN)
			Serial.println("MAC address HP tidak sesuai format.");
		else
		{
			file.write((const uint8_t *)client->data, client->len);
			success = 1;
			Serial.println("Berhasil menyimpan MAC address HP.");
			if (DEBUG_MODE)
			{
				Serial.println("Alamat HP : ");
				printBytes((const uint8_t *)client->data, client->len, NULL, 0);
				Serial.println();
			}
		}
	}
	file.close();
	return success ? BT_SUCCESS : BT_FAIL;
}

int deleteStoredCredImp(void)
{
	SPIFFS.remove("/userPin.txt");
	SPIFFS.remove("/userID.ini");
	return BT_SUCCESS;
}

void toggleAlarm(int enable)
{
	if (enable == BT_ENABLE)
		Serial.printf("ALARM ON!!!!\n");
	else
		Serial.printf("ALARM OFF!!!\n");
}

int setAlarmImp(int enable, int duration)
{
	static int is_active = BT_DISABLE; // Ticker aktif?
	if (is_active == BT_ENABLE)
	{
#if DEBUG_MODE == 1
		Serial.printf("Alarm ticker off\n");
#endif // DEBUG_MODE
		toggleAlarm(BT_DISABLE);
		alarm_ticker.detach();
	}
	if (enable == BT_ENABLE)
	{
#if DEBUG_MODE == 1
		Serial.printf("Alarm ticker on\n");
#endif // DEBUG_MODE
		toggleAlarm(BT_ENABLE);
		alarm_ticker.once(duration, toggleAlarm, BT_DISABLE);
	}
	is_active = enable;
	return BT_SUCCESS;
}

void sendTimeoutToEventQueue()
{
	bt_buffer timeout;
	if (raise_event(&timeout, EVENT_TIMEOUT, NULL, 0) == BT_SUCCESS)
		xQueueSend(qFsmEvent, &timeout, 0);
}

int setTimeoutImp(int enable, int duration)
{
	static int is_active = BT_DISABLE; // Ticker aktif?
	if (is_active == BT_ENABLE)
	{
#if DEBUG_MODE == 1
		Serial.printf("Timeout ticker off\n");
#endif // DEBUG_MODE
		timeout_ticker.detach();
	}
	if (enable == BT_ENABLE)
	{
#if DEBUG_MODE == 1
		Serial.printf("Timeout ticker on\n");
#endif // DEBUG
		timeout_ticker.attach(duration, sendTimeoutToEventQueue);
	}
	is_active = enable;
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

void disconnectImp(void)
{
	SerialBT.disconnect();
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
	pinMode(RELAY, OUTPUT);
}

void onBTInputInterface(const uint8_t *buffer, size_t blen)
{
	bt_buffer bt_in;
	if (DEBUG_MODE)
		Serial.printf("HP: %u :\n", blen);
	if (blen <= BT_BUF_LEN_BYTE)
	{
		if (DEBUG_MODE)
		{
			Serial.write(buffer, blen);
			Serial.println();
			printBytes(buffer, blen, NULL, 0);
		}
		// onBTInput(buffer, blen);
		if (raise_event(&bt_in, EVENT_BT_INPUT, buffer, blen) == BT_SUCCESS)
			xQueueSend(qFsmEvent, &bt_in, 0);
	}
	else
	{
		for (size_t i = 0; i < blen; i += BT_BUF_LEN_BYTE)
		{
			size_t k = (blen - i > BT_BUF_LEN_BYTE) ? BT_BUF_LEN_BYTE : (blen - i);
			if (DEBUG_MODE)
			{
				Serial.write(buffer + i, k);
				// printBytes(buffer, blen, NULL, 0);
			}
			// onBTInput(buffer + i, k);
			if (raise_event(&bt_in, EVENT_BT_INPUT, buffer + i, k) == BT_SUCCESS)
				xQueueSend(qFsmEvent, &bt_in, 0);
			delay(20);
		}
		if (raise_event(&bt_in, EVENT_BT_INPUT_END, NULL, 0) == BT_SUCCESS)
			xQueueSend(qFsmEvent, &bt_in, 0);
	}
}

int loadPKImp(uint8_t *keybuf, size_t keylen)
{
	// Load public key hp
	mbedtls_pk_free(&encrypt_pk);
	mbedtls_entropy_free(&encrypt_entropy);
	mbedtls_ctr_drbg_free(&encrypt_ctr_drbg);

	mbedtls_pk_init(&encrypt_pk);
	mbedtls_entropy_init(&encrypt_entropy);
	mbedtls_ctr_drbg_init(&encrypt_ctr_drbg);

	int ret;
	if ((ret = mbedtls_ctr_drbg_seed(&encrypt_ctr_drbg, mbedtls_entropy_func,
									 &encrypt_entropy, NULL, 0)) != 0)
	{
		// public key error
		if (DEBUG_MODE)
			printError(ret);
		return BT_FAIL;
	}
	else if ((ret = mbedtls_pk_parse_public_key(&encrypt_pk, (const uint8_t *)keybuf, keylen)) != 0)
	{
		// public key error
		if (DEBUG_MODE)
			printError(ret);
		return BT_FAIL;
	}
	return BT_SUCCESS;
}

// param:
// nonce : bt_buffer berisi cipherkey yang baru
// variable non-lokal:
// aes : context untuk cipher AES dari mbedtls
// symkey : array yang menyimpan cipherkey lama
int setCipherkeyImp(const bt_buffer *nonce)
{
	// Load decrypt cipher dengan kunci baru
	mbedtls_aes_free(&aes);
	mbedtls_aes_init(&aes);
	int kx_ret = 0;
	if (nonce->len != BT_BLOCK_SIZE_BYTE) // Pastikan panjang cipherkey sesuai, 128 bit/16 byte
		return BT_FAIL;
	if ((kx_ret = mbedtls_aes_setkey_dec(&aes, (const uint8_t *)nonce->data, BT_BLOCK_SIZE_BIT)) != 0)
	{
		if (DEBUG_MODE)
			printError(kx_ret);
		mbedtls_aes_free(&aes);
		mbedtls_aes_init(&aes);
		kx_ret = mbedtls_aes_setkey_dec(&aes, (const unsigned char *)symkey, BT_BLOCK_SIZE_BIT);
		return BT_FAIL;
	}
	// Simpan cipherkey terbaru di SPIFFS
	int success = 0;
	File file = SPIFFS.open("/userKey.txt", FILE_WRITE);
	{
		if (!file) // File tidak bisa dibuka
		{
			Serial.printf("Tidak bisa menyimpan kunci terbaru");
			mbedtls_aes_free(&aes);
			mbedtls_aes_init(&aes);
			kx_ret = mbedtls_aes_setkey_dec(&aes, (const unsigned char *)symkey, BT_BLOCK_SIZE_BIT);
		}
		else
		{
			success = 1;
			file.write((const uint8_t *)nonce->data, BT_BLOCK_SIZE_BYTE);
			if (DEBUG_MODE)
			{
				Serial.println("Berhasil menyimpan kunci terbaru:");
				printBytes((const uint8_t *)nonce->data, nonce->len, NULL, 0);
			}
		}
	}
	file.close();

	if (success) // update symkey, yang menyimpan cipherkey lama
	{
		memcpy(symkey, nonce->data, nonce->len);
		return BT_SUCCESS;
	}
	else
		return BT_FAIL;
}

int writeBTRSAImp(const bt_buffer *out)
{
	// Encrypt
	uint8_t encrypted[1024];
	size_t elen;
	int ret;
	if ((ret = mbedtls_pk_encrypt(&encrypt_pk, (const uint8_t *)out->data, out->len,
								  encrypted, &elen, sizeof(encrypted),
								  mbedtls_ctr_drbg_random, &encrypt_ctr_drbg)) != 0)
	{
		if (DEBUG_MODE)
			printError(ret);
		return BT_FAIL;
	}
	else // encrypt ok
	{
		if (DEBUG_MODE)
		{
			const char *header = "Mengirim: ";
			printBytes(encrypted, elen, header, strlen(header));
		}
		SerialBT.write(encrypted, elen);
		return 0;
	}
}

int setDiscoverabilityImp(int enable)
{
	uint8_t mac[6];
	String id = "ImmobilizerITB-";
	bool to_enable = (enable == BT_ENABLE);
	// Use MAC address as unique Immobilizer ID to advertise the connection
	if (esp_efuse_mac_get_default(mac) != ESP_OK)
		// SerialBT.begin("ImmobilizerITB-01");
		id.concat("01");
	else
	{
		// Use MAC address as unique Immobilizer ID to advertise the connection
		for (int i = 0; i < 6; i++)
			id.concat(String(mac[i], HEX));
	}
	bool ret = SerialBT.begin(id, false, to_enable);
	return ret ? BT_SUCCESS : BT_FAIL;
}
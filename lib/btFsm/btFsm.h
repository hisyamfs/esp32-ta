#ifndef BT_FSM_H
#define BT_FSM_H

#include "stddef.h"
#include "stdint.h"

/** Helper functions, variables, and constants **/
#define BT_BUF_LEN_BYTE 32
#define BT_BUF_LEN_BIT 256
#define BT_BLOCK_SIZE_BYTE 16
#define BT_BLOCK_SIZE_BIT 128
#define BT_SUCCESS 0
#define BT_FAIL -1
#define BT_ENABLE 1
#define BT_DISABLE 0
#define BT_ADDR_LEN 6

typedef enum BTReply
{
    NACK = '0',
    ACK = '1',
    ERR = '2'
} bt_reply;

typedef enum BTRequest
{
    REQUEST_NOTHING = '0',
    REQUEST_UNLOCK,         // 1
    REQUEST_CHANGE_PIN,     // 2
    REQUEST_REGISTER_PHONE, // 3
    REQUEST_REMOVE_PHONE,   // 4
    REQUEST_DISABLE         // 5
} bt_request;

typedef enum BTEvent
{
    EVENT_TRANSITION,
    EVENT_BT_INPUT,
    EVENT_BT_OUTPUT,
    EVENT_BT_CONNECT,
    EVENT_BT_DISCONNECT,
    EVENT_TIMEOUT,
    EVENT_ERROR,
    EVENT_ALARM_OFF,
    EVENT_ENGINE_OFF,
    EVENT_S_INPUT, // for debugging purposes
    EVENT_SET_CREDENTIAL
} bt_event;

typedef struct BTBuffer
{
    uint8_t data[BT_BUF_LEN_BYTE];
    size_t len;
    bt_event event;
} bt_buffer;

/* State enum declaration, to enforce correctness */
typedef enum
{
    STATE_ERR = 0,
    STATE_DISCONNECT,
    STATE_CONNECT,
    STATE_CHALLENGE,
    STATE_VERIFICATION,
    STATE_PIN,
    STATE_UNLOCK,
    STATE_NEW_PIN,
    STATE_DELETE,
    STATE_ALARM,
    STATE_KEY_EXCHANGE,
    STATE_REGISTER
} fsm_state;

/* Initialize bt_buffer structure */
void init_bt_buffer(bt_buffer *buffer);

/* Initialize the FSM interface, static variables, and states */
int init_btFsm(void (*announceStateImp)(fsm_state),
               int (*generateNonceImp)(bt_buffer *),
               int (*sendReplyImp)(bt_reply),
               int (*writeBTImp)(const bt_buffer *),
               int (*decryptBTImp)(const bt_buffer *, bt_buffer *),
               int (*storePINImp)(bt_buffer *),
               int (*deleteStoredCredentialImp)(void),
               int (*setAlarmImp)(int, int),
               int (*unpairBlacklistImp)(const bt_buffer *),
               void (*setImmobilizerImp)(int),
               void (*handleErrorImp)(void));

/* Check if two buffer store the same data */
int compareBT(const bt_buffer *buf1, const bt_buffer *buf2);

/* Parse user request from a buffer*/
bt_request parse_request(const bt_buffer *buffer);

/* FSM events */
void onBTInput(const uint8_t *data, size_t len);
void onSInput(const uint8_t *data, size_t len);
void onEngineOff();
void onTimeout();
void onBTConnect(const uint8_t *addr, size_t len);
void onBTDisconnect(const uint8_t *addr, size_t len);
void onTransition();

/* Set user credentials */
int load_user_cred(const uint8_t *pin, size_t plen, const uint8_t *addr, size_t alen);
int set_user_pin(const uint8_t *pin, size_t plen);

fsm_state get_current_state();
unsigned int get_registration_status();

#endif // !BT_FSM_H
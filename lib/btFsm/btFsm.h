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
#define BT_FAIL 1
#define BT_ENABLE 1
#define BT_DISABLE 0

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
    EVENT_NOTHING,
    EVENT_BT_INPUT,
    EVENT_BT_OUTPUT,
    EVENT_BT_CONNECT,
    EVENT_BT_DISCONNECT,
    EVENT_TIMEOUT,
    EVENT_ERROR,
    EVENT_ALARM_OFF,
    EVENT_ENGINE_OFF,
    EVENT_S_INPUT // for debugging purposes
} bt_event;

typedef struct BTBuffer
{
    bt_event event;
    uint8_t data[BT_BUF_LEN_BYTE];
    size_t len;
} bt_buffer;

/* State enum declaration, to enforce correctness */
typedef enum
{
    STATE_ERR = 0,
    STATE_DEF,
    STATE_ID_CHECK,
    STATE_CHALLENGE,
    STATE_VERIFICATION,
    STATE_PIN,
    STATE_UNLOCK,
    STATE_NEW_PIN,
    STATE_ALARM,
    STATE_KEY_EXCHANGE,
    STATE_REGISTER
} fsm_state;

/* State function, implements each state */
void state_err(bt_buffer *param);
void state_def(bt_buffer *param);
void state_id_check(bt_buffer *param);
void state_challenge(bt_buffer *param);
void state_verification(bt_buffer *param);
void state_pin(bt_buffer *param);
void state_unlock(bt_buffer *param);
void state_new_pin(bt_buffer *param);
void state_alarm(bt_buffer *param);
void state_register(bt_buffer *param);

/* Initialize bt_buffer structure */
void init_bt_buffer(bt_buffer *buffer);

/* Check if two buffer store the same data */
int compareBT(const bt_buffer *buf1, const bt_buffer *buf2);

/* Parse user request from a buffer*/
bt_request parse_request(bt_buffer *buffer);

int init_btFsm(
    void (*announceStateImp)(fsm_state),
    int (*readBTInputImp)(bt_buffer *),
    int (*readSInputImp)(bt_buffer *),
    int (*generateNonceImp)(bt_buffer *),
    int (*sendReplyImp)(bt_reply),
    int (*writeBTImp)(bt_buffer *),
    int (*checkUserIDImp)(bt_buffer *),
    int (*checkUserPINImp)(bt_buffer *),
    int (*decryptBTImp)(bt_buffer *, bt_buffer *),
    int (*storePINImp)(bt_buffer *),
    int (*soundAlarmImp)(),
    void (*setImmobilizerImp)(int),
    int (*checkEngineOffImp)(),
    void (*handleErrorImp)());

void run_btFsm();
fsm_state get_current_state();

#endif // !BT_FSM_H
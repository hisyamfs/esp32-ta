#ifndef BT_FSM_H
#define BT_FSM_H

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
void state_err();
void state_def();
void state_id_check();
void state_challenge();
void state_verification();
void state_pin();
void state_unlock();
void state_new_pin();
void state_alarm();
void state_register();

/** Helper functions, variables, and constants **/
#define BT_BUF_LEN_BYTE 32
#define BT_BUF_LEN_BIT 256
#define BT_BLOCK_SIZE_BYTE 16
#define BT_BLOCK_SIZE_BIT 128
#define BT_SUCCESS 0
#define BT_FAIL 1
#define BT_ENABLE 1
#define BT_DISABLE 0

typedef struct BTBuffer
{
    unsigned char data[BT_BUF_LEN_BYTE];
    unsigned int len;
} bt_buffer;

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

/* Initialize bt_buffer structure */
void init_bt_buffer(bt_buffer *buffer);

/* Check if two buffer store the same data */
int compareBT(bt_buffer buf1, bt_buffer buf2);

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
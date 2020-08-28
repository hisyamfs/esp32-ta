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

/* State table, holds the pointer to each state implementation */
void(*state_table[]) () =
    {
        state_err,
        state_def,
        state_id_check,
        state_challenge,
        state_verification,
        state_pin,
        state_unlock,
        state_new_pin,
        state_alarm,
        state_register};

/* Holds the current and next state */
static fsm_state current_state;

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

/* Input & Output Buffer for FSM */
static bt_buffer inbuf, outbuf, nonce;
static bt_request user_request;

/* FSM events handler */
static void (*announceState)(fsm_state next_state); // for debugging purpose

// read incoming data, returns how many bytes are incoming, returns
// non-0 if there are incoming data
static int (*readBTInput)(bt_buffer *inbuf);

// read serial monitor, and load it into output buffer, returns non-0
// if there are incoming data. For debugging purposes.
static int (*readSInput)(bt_buffer *outbuf);

// generate a random 16 character string
static int (*generateNonce)(bt_buffer *nonce);

// send device reply: ACK, NACK, and ERR, downstream
static int (*sendReply)(bt_reply status);

// send data held in output buffer. returns BT_SUCCESS on succesful transfer
static int (*writeBT)(bt_buffer *outbuf);

// check user id based on a buffer data. returns BT_SUCCESS if found.
static int (*checkUserID)(bt_buffer *id);

// check user pin based on a buffer value. returns BT_SUCCESS if it matches.
static int (*checkUserPIN)(bt_buffer *pin);

// decrypt a ciphertext. Returns BT_SUCCESS on succesful decryption
static int (*decryptBT)(bt_buffer *ciphertext, bt_buffer *message);

// store the new pin on device memory. returns BT_SUCCESS on success.
static int (*storePIN)(bt_buffer *pin);

// Turns immobilizer on or off
static void (*setImmobilizer)(int enable);

// Checks if the driver switched the engine off
static int (*checkEngineOff)();

static void (*handleError)();

/* Initialize bt_buffer structure */
void init_bt_buffer(bt_buffer *buffer);

/* Check if two buffer store the same data */
int compareBT(bt_buffer buf1, bt_buffer buf2);

/* Parse user request from a buffer*/
bt_request parse_request(bt_buffer *buffer);

void init_btFsm(
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
    void (*setImmobilizerImp)(int),
    int (*checkEngineOffImp)(),
    void (*handleErrorImp)());

#endif // !BT_FSM_H
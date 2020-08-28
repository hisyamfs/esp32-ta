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

/* State table, holds the pointer to each state implementation */
void(*state_table[]) =
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

/* Holds the current and next state */
static fsm_state current_state;

/** Helper functions, variables, and constants **/
const unsigned int BT_BUF_LEN_BYTE = 16;
const unsigned int BT_BUF_LEN_BIT = 128;
const unsigned int BT_SUCCESS = 0;

typedef struct BTBuffer
{
    unsigned char data[BT_BUF_LEN_BYTE * 2];
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
void (*announceState)(fsm_state next_state); // for debugging purpose

// read incoming data, returns how many bytes are incoming, returns
// non-0 if there are incoming data
int (*readBTInput)(bt_buffer *inbuf);

// read serial monitor, and load it into output buffer, returns non-0
// if there are incoming data. For debugging purposes.
int (*readSInput)(bt_buffer *outbuf);

// generate a random 16 character string
int (*generateNonce)(bt_buffer *nonce);

// send device reply: ACK, NACK, and ERR, downstream
int (*sendReply)(bt_reply status);

// send data held in output buffer. returns BT_SUCCESS on succesful transfer
int (*writeBT)(bt_buffer *outbuf);

// check user id based on a buffer data. returns BT_SUCCESS if found.
int (*checkUserID)(bt_buffer *id);

// check user pin based on a buffer value. returns BT_SUCCESS if it matches.
int (*checkUserPIN)(bt_buffer *pin);

// decrypt a ciphertext. Returns BT_SUCCESS on succesful decryption
int (*decryptBT)(bt_reply *ciphertext, bt_reply *message);

void (*disableImmobilizer) ();

/* Initialize bt_buffer structure */
void init_bt_buffer(bt_buffer *buffer);
int compareBT(bt_buffer buf1, bt_buffer buf2);

/* Parse user request from a buffer*/
bt_request parse_request(bt_buffer *buffer);

#endif // !BT_FSM_H
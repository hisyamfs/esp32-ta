#include "btFsm.h"

/* Input & Output Buffer for FSM */
static bt_buffer inbuf, outbuf, nonce;
static bt_request user_request;

/* State table, holds the pointer to each state implementation */
void (*btFsm_state_table[])() =
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

/* FSM events handler */
static void (*announceState)(fsm_state next_state) = nullptr; // for debugging purpose

// read incoming data, returns how many bytes are incoming, returns
// non-0 if there are incoming data
static int (*readBTInput)(bt_buffer *inbuf) = nullptr;

// read serial monitor, and load it into output buffer, returns non-0
// if there are incoming data. For debugging purposes.
static int (*readSInput)(bt_buffer *outbuf) = nullptr;

// generate a random 16 character string
static int (*generateNonce)(bt_buffer *nonce) = nullptr;

// send device reply: ACK, NACK, and ERR, downstream
static int (*sendReply)(bt_reply status) = nullptr;

// send data held in output buffer. returns BT_SUCCESS on succesful transfer
static int (*writeBT)(bt_buffer *outbuf) = nullptr;

// check user id based on a buffer data. returns BT_SUCCESS if found.
static int (*checkUserID)(bt_buffer *id) = nullptr;

// check user pin based on a buffer value. returns BT_SUCCESS if it matches.
static int (*checkUserPIN)(bt_buffer *pin) = nullptr;

// decrypt a ciphertext. Returns BT_SUCCESS on succesful decryption
static int (*decryptBT)(bt_buffer *ciphertext, bt_buffer *message) = nullptr;

// store the new pin on device memory. returns BT_SUCCESS on success.
static int (*storePIN)(bt_buffer *pin) = nullptr;

// sounds the alarm
static int (*soundAlarm)() = nullptr;

// Turns immobilizer on or off
static void (*setImmobilizer)(int enable) = nullptr;

// Checks if the driver switched the engine off
static int (*checkEngineOff)() = nullptr;

static void (*handleError)() = nullptr;

fsm_state get_current_state()
{
    return current_state;
}

void run_btFsm()
{
    btFsm_state_table[current_state]();
}

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
    void (*handleErrorImp)())
{
    init_bt_buffer(&inbuf);
    init_bt_buffer(&outbuf);
    init_bt_buffer(&nonce);
    user_request = REQUEST_NOTHING;
    current_state = STATE_DEF;

    announceState = announceStateImp;
    if (announceState == nullptr)
        return BT_FAIL;

    readBTInput = readBTInputImp;
    if (readBTInput == nullptr)
        return BT_FAIL;

    readSInput = readSInputImp;
    if (readSInput == nullptr)
        return BT_FAIL;

    generateNonce = generateNonceImp;
    if (generateNonce == nullptr)
        return BT_FAIL;

    sendReply = sendReplyImp;
    if (sendReply == nullptr)
        return BT_FAIL;

    writeBT = writeBTImp;
    if (writeBT == nullptr)
        return BT_FAIL;

    checkUserID = checkUserIDImp;
    if (checkUserID == nullptr)
        return BT_FAIL;

    checkUserPIN = checkUserPINImp;
    if (checkUserPIN == nullptr)
        return BT_FAIL;

    decryptBT = decryptBTImp;
    if (decryptBT == nullptr)
        return BT_FAIL;

    storePIN = storePINImp;
    if (storePIN == nullptr)
        return BT_FAIL;

    soundAlarm = soundAlarmImp;
    if (soundAlarm == nullptr)
        return BT_FAIL;

    setImmobilizer = setImmobilizerImp;
    if (setImmobilizer == nullptr)
        return BT_FAIL;

    checkEngineOff = checkEngineOffImp;
    if (checkEngineOff == nullptr)
        return BT_FAIL;

    handleError = handleErrorImp;
    if (handleError == nullptr)
        return BT_FAIL;

    return BT_SUCCESS;
}

void state_err()
{
    handleError();
}

void state_def()
{
    if (readBTInput(&inbuf))
    {
        user_request = parse_request(&inbuf);
        switch (user_request)
        {
        case REQUEST_UNLOCK:
        case REQUEST_CHANGE_PIN:
        case REQUEST_REMOVE_PHONE:
        {
            sendReply(ACK);
            fsm_state next_state = STATE_ID_CHECK;
            announceState(next_state);
            current_state = next_state;
            break;
        }
        default: // REQUEST_NOTHING and other unimplemented feature (e.g. register)
        {
            sendReply(NACK);
            fsm_state next_state = STATE_DEF;
            announceState(next_state);
            current_state = next_state;
            break;
        }
        }
    }
    if (readSInput(&outbuf))
    {
        writeBT(&outbuf);
    }
}

void state_id_check()
{
    if (readBTInput(&inbuf))
    {
        if (checkUserID(&inbuf) == BT_SUCCESS)
        {
            sendReply(ACK);
            announceState(STATE_CHALLENGE);
            current_state = STATE_CHALLENGE;
        }
        else
        {
            sendReply(NACK);
            announceState(STATE_DEF);
            current_state = STATE_DEF;
        }
    }
}

void state_challenge()
{
    if (generateNonce(&nonce) == BT_SUCCESS)
    {
        writeBT(&nonce);
        current_state = STATE_VERIFICATION;
        announceState(current_state);
    }
    else // Fail to generate nonce, error
    {
        sendReply(NACK);
        announceState(STATE_ERR);
        current_state = STATE_ERR;
    }
}

void state_verification()
{
    if (readBTInput(&inbuf))
    {
        bt_buffer response;
        init_bt_buffer(&response);
        if (decryptBT(&inbuf, &response) == BT_SUCCESS)
        {
            // compare the response with the nonce
            if (compareBT(&nonce, &response) == BT_SUCCESS)
            {
                sendReply(ACK);
                announceState(STATE_PIN);
                current_state = STATE_PIN;
            }
            else
            {
                sendReply(NACK);
                announceState(STATE_ALARM);
                current_state = STATE_ALARM;
            }
        }
        else
        {
            sendReply(ERR);
            announceState(STATE_ERR);
            current_state = STATE_ERR;
        }
    }
}

void state_pin()
{
    if (readBTInput(&inbuf))
    {
        bt_buffer pin;
        init_bt_buffer(&pin);
        if (decryptBT(&inbuf, &pin) == BT_SUCCESS)
        {
            // compare the response with the nonce
            if (checkUserPIN(&pin) == BT_SUCCESS)
            {
                sendReply(ACK);
                fsm_state next_state = STATE_DEF;
                switch (user_request)
                {
                case REQUEST_UNLOCK:
                {
                    setImmobilizer(BT_DISABLE);
                    next_state = STATE_UNLOCK;
                    break;
                }
                case REQUEST_CHANGE_PIN:
                    next_state = STATE_NEW_PIN;
                    break;
                default:
                    next_state = STATE_DEF;
                }
                announceState(next_state);
                current_state = next_state;
            }
            else
            {
                sendReply(NACK);
                announceState(STATE_ALARM);
                current_state = STATE_ALARM;
            }
        }
        else
        {
            sendReply(ERR);
            announceState(STATE_ERR);
            current_state = STATE_ERR;
        }
    }
}

void state_unlock()
{
    if (checkEngineOff() == BT_SUCCESS)
    {
        setImmobilizer(BT_ENABLE);
        sendReply(ACK);
        announceState(STATE_DEF);
        current_state = STATE_DEF;
    }
}

void state_new_pin()
{
    if (readBTInput(&inbuf))
    {
        bt_buffer pin;
        init_bt_buffer(&pin);
        if (decryptBT(&inbuf, &pin) == BT_SUCCESS)
        {
            if (storePIN(&pin) == BT_SUCCESS)
                sendReply(ACK);
            else
                sendReply(NACK);
            announceState(STATE_DEF);
            current_state = STATE_DEF;
        }
        else
        {
            sendReply(ERR);
            announceState(STATE_ERR);
            current_state = STATE_ERR;
        }
    }
}

void state_alarm()
{
    if (soundAlarm() == BT_SUCCESS)
    {
        sendReply(ACK);
        announceState(STATE_DEF);
        current_state = STATE_DEF;
    }
}

void state_register()
{
    // TODO("Implement the state")
}

/* Initialize bt_buffer structure */
void init_bt_buffer(bt_buffer *buffer)
{
    buffer->len = 0;
    for (int i = 0; i < BT_BLOCK_SIZE_BYTE; i++)
    {
        buffer->data[i] = 0;
    }
}

/* Check if two buffer store the same data */
int compareBT(const bt_buffer *buf1, const bt_buffer *buf2)
{
    int no_mismatch = (buf1->len == buf2->len);
    for (int i = 0; i < buf1->len && i < BT_BLOCK_SIZE_BYTE && no_mismatch; i++)
    {
        no_mismatch = (buf1->data[i] == buf2->data[i]);
    }
    if (no_mismatch)
        return BT_SUCCESS;
    else
        return BT_FAIL;
}

/* Parse user request from a buffer */
bt_request parse_request(bt_buffer *buffer)
{
    int is_req = (buffer->data[0] == '!'); // Request begin with an exclamation mark, e.g. '!1'
    if (!is_req)
        return REQUEST_NOTHING;
    else if (buffer->data[1] <= (char)REQUEST_DISABLE &&
             buffer->data[1] >= (char)REQUEST_NOTHING)
        return (bt_request)buffer->data[1];
    else
        return REQUEST_NOTHING;
}

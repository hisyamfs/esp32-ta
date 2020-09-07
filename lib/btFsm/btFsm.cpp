#include "btFsm.h"
#include "string.h"
#include "Arduino.h"

/* FSM variables */
static bt_buffer nonce, USER_ADDR, USER_PIN;
static bt_request user_request;
static uint is_registered;

/* State function, implements each state */
static void state_err(const bt_buffer *param);
static void state_disconnect(const bt_buffer *param);
static void state_connect(const bt_buffer *param);
static void state_challenge(const bt_buffer *param);
static void state_verification(const bt_buffer *param);
static void state_pin(const bt_buffer *param);
static void state_unlock(const bt_buffer *param);
static void state_new_pin(const bt_buffer *param);
static void state_delete(const bt_buffer *param);
static void state_alarm(const bt_buffer *param);
static void state_key_exchange(const bt_buffer *param);
static void state_register(const bt_buffer *param);

/* State table, holds the pointer to each state implementation */
// typedef enum
// {
//     STATE_ERR = 0,
//     STATE_DISCONNECT,
//     STATE_CONNECT,
//     STATE_CHALLENGE,
//     STATE_VERIFICATION,
//     STATE_PIN,
//     STATE_UNLOCK,
//     STATE_NEW_PIN,
//     STATE_DELETE,
//     STATE_ALARM,
//     STATE_KEY_EXCHANGE,
//     STATE_REGISTER
// } fsm_state;
static void (*btFsm_state_table[])(const bt_buffer *param) =
    {
        state_err,
        state_disconnect,
        state_connect,
        state_challenge,
        state_verification,
        state_pin,
        state_unlock,
        state_new_pin,
        state_delete,
        state_alarm,
        state_key_exchange,
        state_register};

/* Holds the current and next state */
static fsm_state current_state;

/* FSM interfaces */
static void (*announceState)(fsm_state next_state) = nullptr;                       // print the current state, for debugging
static int (*generateNonce)(bt_buffer *nonce) = nullptr;                            // generate a random 16 character string
static int (*sendReply)(bt_reply status) = nullptr;                                 // send device reply: ACK, NACK, and ERR, downstream
static int (*writeBT)(const bt_buffer *outbuf) = nullptr;                           // send data held in output buffer. returns BT_SUCCESS on succesful transfer
static int (*decryptBT)(const bt_buffer *ciphertext, bt_buffer *message) = nullptr; // decrypt a ciphertext. Returns BT_SUCCESS on succesful decryption
static int (*storePIN)(bt_buffer *pin) = nullptr;                                   // store the new pin on device memory. returns BT_SUCCESS on success.
static int (*deleteStoredCredential)(void) = nullptr;                               // Delete user id and pin from device memory
static int (*setAlarm)(int enable, int duration) = nullptr;                         // sounds the alarm
static int (*unpairBlacklist)(const bt_buffer *client) = nullptr;                   // detect and prevent unregistered device from ever pairing again
static void (*setImmobilizer)(int enable) = nullptr;                                // Turns immobilizer on or off
static void (*handleError)(void) = nullptr;                                         // Error handler

// check user id based on a buffer data. returns BT_SUCCESS if found.
static int checkUserID(const bt_buffer *id)
{
    return compareBT(id, &USER_ADDR);
}

// check user pin based on a buffer value. returns BT_SUCCESS if it matches.
static int checkUserPIN(const bt_buffer *pin)
{
    return compareBT(pin, &USER_PIN);
}

static void change_state(fsm_state next_state)
{
    delay(20);
    if (announceState != nullptr)
        announceState(next_state);
    current_state = next_state;
    onTransition();
}

fsm_state get_current_state()
{
    return current_state;
}

static void run_btFsm(const bt_buffer *param)
{
    btFsm_state_table[current_state](param);
}

void onBTInput(const uint8_t *input_data, size_t input_len)
{
    bt_buffer bt_input;
    bt_input.event = EVENT_BT_INPUT;
    bt_input.len = input_len;
    memcpy(&bt_input.data, input_data, input_len);
    run_btFsm(&bt_input);
}

void onSInput(const uint8_t *input_data, size_t input_len)
{
    bt_buffer s_input;
    s_input.event = EVENT_S_INPUT;
    s_input.len = input_len;
    memcpy(&s_input.data, input_data, input_len);
    run_btFsm(&s_input);
}

void onEngineOff()
{
    bt_buffer engine_off;
    init_bt_buffer(&engine_off);
    engine_off.event = EVENT_ENGINE_OFF;
    run_btFsm(&engine_off);
}

void onTimeout()
{
    bt_buffer timeout;
    timeout.event = EVENT_TIMEOUT;
    run_btFsm(&timeout);
}

void onBTConnect(const uint8_t *addr, size_t addr_len)
{
    bt_buffer new_connection;
    new_connection.event = EVENT_BT_CONNECT;
    new_connection.len = addr_len;
    memcpy(&new_connection.data, addr, addr_len);
    run_btFsm(&new_connection);
}

void onBTDisconnect(const uint8_t *addr, size_t addr_len)
{
    bt_buffer disconnected;
    disconnected.event = EVENT_BT_DISCONNECT;
    disconnected.len = addr_len;
    memcpy(&disconnected.data, addr, addr_len);
    run_btFsm(&disconnected);
}

void onTransition()
{
    bt_buffer transition;
    transition.event = EVENT_TRANSITION;
    run_btFsm(&transition);
}

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
               void (*handleErrorImp)(void))
{
    init_bt_buffer(&nonce);
    init_bt_buffer(&USER_PIN);
    init_bt_buffer(&USER_ADDR);
    is_registered = 0;
    user_request = REQUEST_NOTHING;
    current_state = STATE_ERR;

    announceState = announceStateImp;
    if (announceState == nullptr)
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

    decryptBT = decryptBTImp;
    if (decryptBT == nullptr)
        return BT_FAIL;

    storePIN = storePINImp;
    if (storePIN == nullptr)
        return BT_FAIL;

    deleteStoredCredential = deleteStoredCredentialImp;
    if (deleteStoredCredential == nullptr)
        return BT_FAIL;

    setAlarm = setAlarmImp;
    if (setAlarm == nullptr)
        return BT_FAIL;

    unpairBlacklist = unpairBlacklistImp;
    if (unpairBlacklist == nullptr)
        return BT_FAIL;

    setImmobilizer = setImmobilizerImp;
    if (setImmobilizer == nullptr)
        return BT_FAIL;

    handleError = handleErrorImp;
    if (handleError == nullptr)
        return BT_FAIL;

    current_state = STATE_DISCONNECT;
    return BT_SUCCESS;
}

static void state_err(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_TRANSITION:
        handleError();
        break;
    default: // TODO("Fix this")
        handleError();
        break;
    }
}

static void state_disconnect(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_BT_CONNECT:
        if (is_registered && (checkUserID(param) != BT_SUCCESS))
        {
            sendReply(NACK);
            // block the client from ever pairing again
            unpairBlacklist(param);
        }
        else // no registered user yet, or the client is of registered address
        {
            sendReply(ACK);
            change_state(STATE_CONNECT);
        }
        break;
    // case EVENT_TRANSITION:
    //     close_connection();
    //     break;
    default:
        break;
    }
}

static void state_connect(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_BT_INPUT:
        user_request = parse_request(param);
        switch (user_request)
        {
        case REQUEST_UNLOCK:
        case REQUEST_CHANGE_PIN:
        case REQUEST_REMOVE_PHONE:
            if (is_registered)
            {
                sendReply(ACK);
                change_state(STATE_CHALLENGE);
            }
            else
                sendReply(NACK);
            break;
        case REQUEST_REGISTER_PHONE:
            if (!is_registered)
            {
                sendReply(ACK);
                change_state(STATE_KEY_EXCHANGE);
            }
            else
                sendReply(NACK);
            break;
        default: // REQUEST_NOTHING and other unimplemented feature (e.g. register)
            sendReply(NACK);
            break;
        }
        break;
    case EVENT_S_INPUT:
        writeBT(param);
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    default:
        break;
    }
}

static void state_challenge(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_TRANSITION:
        if (generateNonce(&nonce) == BT_SUCCESS)
        {
            writeBT(&nonce);
            change_state(STATE_VERIFICATION);
        }
        else // Fail to generate nonce, error
        {
            sendReply(NACK);
            change_state(STATE_ERR);
        }
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    default:
        break;
    }
}

static void state_verification(const bt_buffer *param)
{
    switch (param->event)
    {
    // case EVENT_TRANSITION:
    //     set_timeout(500, MS); // 500 ms timeout
    //     break;
    case EVENT_BT_INPUT:
        bt_buffer response;
        init_bt_buffer(&response);
        if (decryptBT(param, &response) == BT_SUCCESS)
        {
            // compare the response with the nonce
            if (compareBT(&nonce, &response) == BT_SUCCESS)
            {
                sendReply(ACK);
                change_state(STATE_PIN);
            }
            else // cram mismatch
            {
                sendReply(NACK);
                change_state(STATE_ALARM);
            }
        }
        else // error
        {
            sendReply(ERR);
            change_state(STATE_ERR);
        }
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    case EVENT_TIMEOUT:
        sendReply(NACK);
        change_state(STATE_ALARM);
        break;
    default:
        break;
    }
}

static void state_pin(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_BT_INPUT:
        bt_buffer pin;
        init_bt_buffer(&pin);
        if (decryptBT(param, &pin) == BT_SUCCESS)
        {
            // compare the response with the nonce
            if (checkUserPIN(&pin) == BT_SUCCESS)
            {
                sendReply(ACK);
                fsm_state next_state = STATE_CONNECT;
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
                case REQUEST_REMOVE_PHONE:
                    next_state = STATE_DELETE;
                    break;
                default:
                    next_state = STATE_CONNECT;
                }
                change_state(next_state);
            }
            else
            {
                sendReply(NACK);
                change_state(STATE_ALARM);
            }
        }
        else
        {
            sendReply(ERR);
            change_state(STATE_ERR);
        }
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    default:
        break;
    }
}

static void state_unlock(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_TRANSITION:
        setImmobilizer(BT_DISABLE);
        break;
    case EVENT_S_INPUT:
    case EVENT_ENGINE_OFF:
        setImmobilizer(BT_ENABLE);
        sendReply(ACK);
        change_state(STATE_CONNECT);
        break;
    default:
        break;
    }
}

static void state_new_pin(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_BT_INPUT:
        bt_buffer pin;
        init_bt_buffer(&pin);
        if (decryptBT(param, &pin) == BT_SUCCESS)
        {
            if (storePIN(&pin) == BT_SUCCESS)
            {
                set_user_pin((const uint8_t *)&pin.data, pin.len);
                sendReply(ACK);
            }
            else
                sendReply(NACK);
            change_state(STATE_CONNECT);
        }
        else
        {
            sendReply(ERR);
            change_state(STATE_ERR);
        }
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    default:
        break;
    }
}

static void state_delete(const bt_buffer *param)
{
    // TODO("Implement the state")
    switch (param->event)
    {
    case EVENT_TRANSITION:
        if (deleteStoredCredential() == BT_SUCCESS)
        {
            sendReply(ACK);
            init_bt_buffer(&USER_PIN);
            init_bt_buffer(&USER_ADDR);
            is_registered = 0;
            change_state(STATE_CONNECT);
        }
        else
        {
            sendReply(NACK);
            change_state(STATE_CONNECT);
        }
        break;
    default:
        break;
    }
}

static void state_alarm(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_TRANSITION:
        setAlarm(BT_ENABLE, 3000);
        break;
    case EVENT_S_INPUT:
    case EVENT_TIMEOUT:
        setAlarm(BT_DISABLE, 0);
        sendReply(ACK);
        change_state(STATE_CONNECT);
        break;
    default:
        break;
    }
}

static void state_key_exchange(const bt_buffer *param)
{
    // TODO("Implement the state")
}

static void state_register(const bt_buffer *param)
{
    // TODO("Implement the state")
}

/* Initialize bt_buffer structure */
void init_bt_buffer(bt_buffer *buffer)
{
    buffer->event = EVENT_TRANSITION;
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

/* Loads user credentials after FSM initialization */
int load_user_cred(const uint8_t *pin, size_t plen, const uint8_t *addr, size_t alen)
{
    if (plen > BT_BLOCK_SIZE_BYTE || alen != BT_ADDR_LEN || plen == 0)
    {
        is_registered = 0;
        return BT_FAIL;
    }
    else
    {
        USER_PIN.event = EVENT_SET_CREDENTIAL;
        USER_PIN.len = plen;
        memcpy(&USER_PIN.data, pin, plen);
        USER_ADDR.event = EVENT_SET_CREDENTIAL;
        USER_ADDR.len = alen;
        memcpy(&USER_ADDR.data, addr, alen);
        is_registered = 1;
        return BT_SUCCESS;
    }
}

int set_user_pin(const uint8_t *pin, size_t plen)
{
    if (plen > BT_BLOCK_SIZE_BYTE)
        return BT_FAIL;
    else
    {
        USER_PIN.event = EVENT_SET_CREDENTIAL;
        USER_PIN.len = plen;
        memcpy(&USER_PIN.data, pin, plen);
        // is_registered = 1;
        return BT_SUCCESS;
    }
}

/* Parse user request from a buffer */
bt_request parse_request(const bt_buffer *buffer)
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

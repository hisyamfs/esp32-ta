#include "btFsm.h"
#include "string.h"
#include "Arduino.h"

/* FSM variables */
static bt_buffer nonce, USER_ADDR, USER_PIN, client;
static volatile bt_request user_request;
static volatile bt_reply IS_REGISTERED;
static uint8_t keybuf[1024];
static size_t keylen;

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
static void state_unlock_disconnect(const bt_buffer *param);

/*** 
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
    STATE_REGISTER,
    STATE_UNLOCK_DISCONNECT
} fsm_state;
***/
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
        state_register,
        state_unlock_disconnect};

/* Holds the current and next state */
static fsm_state current_state;

/* FSM interfaces */
static void (*announceState)(fsm_state next_state) = nullptr;                       // print the current state, for debugging
static int (*generateNonce)(bt_buffer *nonce) = nullptr;                            // generate a random 16 character string
static int (*sendReply)(bt_reply status) = nullptr;                                 // send device reply: ACK, NACK, and ERR, downstream
static int (*writeBT)(const bt_buffer *outbuf) = nullptr;                           // send data held in output buffer. returns BT_SUCCESS on succesful transfer
static int (*decryptBT)(const bt_buffer *ciphertext, bt_buffer *message) = nullptr; // decrypt a ciphertext. Returns BT_SUCCESS on succesful decryption
static int (*storeCredential)(bt_buffer *pin, bt_buffer *client) = nullptr;         // store the new pin on device memory. returns BT_SUCCESS on success.
static int (*deleteStoredCredential)(void) = nullptr;                               // Delete user id and pin from device memory
static int (*loadPK)(uint8_t *keybuf, size_t keylen) = nullptr;                     // Load RSA Pubkey for the RSA Cipher
static int (*setCipherkey)(const bt_buffer *nonce) = nullptr;                       // Load AES Symkey for the AES-128 Cipher
static int (*writeBTRSA)(const bt_buffer *out) = nullptr;                           // send RSA encrypted data
static int (*setAlarm)(int enable, int duration) = nullptr;                         // sounds the alarm
static int (*setTimeout)(int enable, int duration) = nullptr;                       // create a timer to trigger a connection timeout event
static int (*unpairBlacklist)(const bt_buffer *client) = nullptr;                   // detect and prevent unregistered device from ever pairing again
static void (*setImmobilizer)(int enable) = nullptr;                                // Turns immobilizer on or off
static void (*handleError)(void) = nullptr;                                         // Error handler
static void (*disconnect)(void) = nullptr;                                          // Disconnect bluetooth

// check user id based on a buffer data. returns BT_SUCCESS if found.
static int checkUserID(const bt_buffer *id)
{
    return compareBT(id, &USER_ADDR);
}

// check user pin based on a buffer value. returns BT_SUCCESS if it matches.
static int checkUserPIN(const bt_buffer *pin)
{
    bt_buffer depadded_pin;
    init_bt_buffer(&depadded_pin);
    depadded_pin.len = strlen((const char *)pin->data);
    memcpy(&depadded_pin.data, pin->data, depadded_pin.len);
    return compareBT(&depadded_pin, &USER_PIN);
}

static void change_state(fsm_state next_state)
{
    delay(20);
    if (announceState != nullptr)
        announceState(next_state);
    setTimeout(BT_DISABLE, 0);
    current_state = next_state;
    onTransition();
}

fsm_state get_current_state()
{
    return current_state;
}

unsigned int get_registration_status()
{
    return (unsigned int)IS_REGISTERED;
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
    if (bt_input.len > BT_BUF_LEN_BYTE)
        bt_input.len = BT_BUF_LEN_BYTE;
    memcpy(&bt_input.data, input_data, bt_input.len);
    run_btFsm(&bt_input);
}

void onBTInputEnd()
{
    bt_buffer bt_input_end;
    bt_input_end.event = EVENT_BT_INPUT_END;
    run_btFsm(&bt_input_end);
}

void onSInput(const uint8_t *input_data, size_t input_len)
{
    bt_buffer s_input;
    s_input.event = EVENT_S_INPUT;
    s_input.len = input_len;
    if (s_input.len > BT_BUF_LEN_BYTE)
        s_input.len = BT_BUF_LEN_BYTE;
    memcpy(&s_input.data, input_data, s_input.len);
    run_btFsm(&s_input);
}

void onEngineEvent(int data)
{
    bt_buffer engine_data;
    init_bt_buffer(&engine_data);
    engine_data.event = EVENT_ENGINE;
    engine_data.len = 1;
    engine_data.data[0] = data;
    run_btFsm(&engine_data);
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
               int (*storeCredentialImp)(bt_buffer *, bt_buffer *),
               int (*deleteStoredCredentialImp)(void),
               int (*loadPKImp)(uint8_t *, size_t),
               int (*setCipherkeyImp)(const bt_buffer *),
               int (*writeBTRSAImp)(const bt_buffer *),
               int (*setAlarmImp)(int, int),
               int (*setTimeoutImp)(int, int),
               int (*unpairBlacklistImp)(const bt_buffer *),
               void (*setImmobilizerImp)(int),
               void (*handleErrorImp)(void),
               void (*disconnectImp)(void))
{
    init_bt_buffer(&nonce);
    init_bt_buffer(&USER_PIN);
    init_bt_buffer(&USER_ADDR);
    IS_REGISTERED = NACK;
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

    storeCredential = storeCredentialImp;
    if (storeCredential == nullptr)
        return BT_FAIL;

    deleteStoredCredential = deleteStoredCredentialImp;
    if (deleteStoredCredential == nullptr)
        return BT_FAIL;

    loadPK = loadPKImp;
    if (loadPK == nullptr)
        return BT_FAIL;

    setCipherkey = setCipherkeyImp;
    if (setCipherkey == nullptr)
        return BT_FAIL;

    writeBTRSA = writeBTRSAImp;
    if (writeBTRSA == nullptr)
        return BT_FAIL;

    setAlarm = setAlarmImp;
    if (setAlarm == nullptr)
        return BT_FAIL;

    setTimeout = setTimeoutImp;
    if (setTimeout == nullptr)
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

    disconnect = disconnectImp;
    if (disconnect == nullptr)
        return BT_FAIL;

    keylen = 0;
    for (int i = 0; i < 1024; i++)
    {
        keybuf[i] = 0;
    }

    current_state = STATE_DISCONNECT;
    announceState(current_state);
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
        if ((IS_REGISTERED == ACK) && (checkUserID(param) != BT_SUCCESS))
        {
            sendReply(NACK);
            // block the client from ever pairing again
            unpairBlacklist(param);
        }
        else // no registered user yet, or the client is of registered address
        {
            client.len = BT_ADDR_LEN;
            memcpy(&client.data, param->data, client.len);
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
        if (IS_REGISTERED == ACK)
        {
            switch (user_request)
            {
            case REQUEST_UNLOCK:
            case REQUEST_CHANGE_PIN:
            case REQUEST_REMOVE_PHONE:
                sendReply(ACK);
                change_state(STATE_CHALLENGE);
                break;
            default: // REQUEST_NOTHING and other unimplemented feature (e.g. register)
                sendReply(NACK);
                break;
            }
        }
        else
        {
            switch (user_request)
            {
            case REQUEST_REGISTER_PHONE:
                sendReply(ACK);
                change_state(STATE_KEY_EXCHANGE);
                break;
            default: // REQUEST_NOTHING and other unimplemented feature (e.g. register)
                sendReply(NACK);
                break;
            }
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
    case EVENT_TRANSITION:
        setTimeout(BT_ENABLE, 5); // 5 s timeout for response
        break;
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
        change_state(STATE_CONNECT);
        break;
    default:
        break;
    }
}

static void state_pin(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_TRANSITION:
        setTimeout(BT_ENABLE, 60); // 1 minute to enter pin
        break;
    case EVENT_BT_INPUT:
        bt_buffer pin;
        init_bt_buffer(&pin);
        if (decryptBT(param, &pin) == BT_SUCCESS)
        {
            // compare the response with the nonce
            if (checkUserPIN(&pin) == BT_SUCCESS)
            {
                setAlarm(BT_DISABLE, 0);
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
    case EVENT_TIMEOUT:
        sendReply(NACK);
        change_state(STATE_CONNECT);
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
    {
        setImmobilizer(BT_DISABLE);
        break;
    }
    case EVENT_BT_INPUT:
    {
        user_request = parse_request(param);
        // TODO: Buat agar disini baca kondisi mesin beneran
        int is_engine_off = BT_SUCCESS;
        // request unlock berfungsi sbg toggle pada state unlock
        if (user_request == REQUEST_UNLOCK && is_engine_off == BT_SUCCESS)
        {
            setImmobilizer(BT_ENABLE);
            sendReply(ACK);
            change_state(STATE_CONNECT);
        }
        else
        {
            sendReply(NACK);
        }
        break;
    }
    case EVENT_S_INPUT: // For debugging
    case EVENT_ENGINE:
    {
        setImmobilizer(BT_ENABLE);
        sendReply(ACK);
        change_state(STATE_CONNECT);
        break;
    }
    case EVENT_BT_DISCONNECT:
    {
        change_state(STATE_UNLOCK_DISCONNECT);
        break;
    }
    default:
        break;
    }
}

static void state_unlock_disconnect(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_BT_CONNECT:
        if (checkUserID(param) != BT_SUCCESS)
        {
            sendReply(NACK);
            // block the client from ever pairing again
            unpairBlacklist(param);
        }
        else // the client is of registered addres
        {
            client.len = BT_ADDR_LEN;
            memcpy(&client.data, param->data, client.len);
            sendReply(ACK_UNL);
            change_state(STATE_UNLOCK);
        }
        break;
    case EVENT_S_INPUT:
    case EVENT_ENGINE:
        change_state(STATE_DISCONNECT);
        break;
    default:
        break;
    }
}

static void state_new_pin(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_TRANSITION:
        setTimeout(BT_ENABLE, 60); // 60 s timeout to enter new pin
        break;
    case EVENT_BT_INPUT:
        bt_buffer pin;
        init_bt_buffer(&pin);
        if (decryptBT(param, &pin) == BT_SUCCESS)
        {
            if (storeCredential(&pin, &client) == BT_SUCCESS)
            {
                if (load_user_cred((const uint8_t *)&pin.data, pin.len,
                                   (const uint8_t *)&client.data, client.len) == BT_SUCCESS)
                    sendReply(ACK);
                else
                    sendReply(NACK);
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
    case EVENT_TIMEOUT:
        sendReply(NACK);
        change_state(STATE_CONNECT);
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
            init_bt_buffer(&USER_PIN);
            init_bt_buffer(&USER_ADDR);
            IS_REGISTERED = NACK;
            sendReply(ACK);
        }
        else
            sendReply(NACK);
        change_state(STATE_CONNECT);
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
        setAlarm(BT_ENABLE, BT_ALARM_DURATION_SEC);
        change_state(STATE_CONNECT);
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    default:
        break;
    }
}

static void state_key_exchange(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_TRANSITION:
        keylen = 0;
        setTimeout(BT_ENABLE, 60); // 60 s timeout for the phone to send it's public key
        break;
    case EVENT_BT_INPUT:
        memcpy(keybuf + keylen, param->data, param->len);
        keylen += param->len;
        // announceState(STATE_KEY_EXCHANGE);
        break;
    case EVENT_BT_INPUT_END:
        // All PK bytes have been received, load the PK, generate the AES symkey, and send it over an encrypted channel
        keylen++;
        keybuf[keylen] = '\0';
        // Load PK
        if ((loadPK(keybuf, keylen) == BT_SUCCESS) &&
            (generateNonce(&nonce) == BT_SUCCESS))
        {
            if (setCipherkey(&nonce) == BT_SUCCESS)
            {
                writeBTRSA(&nonce);
                delay(20);
                sendReply(ACK);
                change_state(STATE_NEW_PIN);
            }
            else
            {
                sendReply(NACK);
                change_state(STATE_CONNECT);
            }
        }
        else
        {
            sendReply(NACK);
            change_state(STATE_CONNECT);
        }
        break;
    case EVENT_TIMEOUT:
        sendReply(NACK);
        change_state(STATE_CONNECT);
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    default:
        break;
    }
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
    for (int i = 0; i < buf1->len && i < BT_BUF_LEN_BYTE && no_mismatch; i++)
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
        IS_REGISTERED = NACK;
        // setImmobilizer(BT_DISABLE); // debugging
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
        IS_REGISTERED = ACK;
        // setImmobilizer(BT_ENABLE);
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
    else if (buffer->data[1] <= (uint8_t)REQUEST_DISABLE &&
             buffer->data[1] >= (uint8_t)REQUEST_NOTHING)
        return (bt_request)buffer->data[1];
    else
        return REQUEST_NOTHING;
}

#include "btFsm.h"
#include "string.h"
#include "Arduino.h"

/* FSM variables */
static bt_buffer nonce;                  /** 16 random numbers for challenge-response step */
static bt_buffer USER_ADDR;              /** Bluetooth MAC address of the registered account */
static bt_buffer USER_PIN;               /** PIN of the registered acoount */
static bt_buffer client;                 /** Bluetooth MAC address of the incoming client */
static volatile bt_request user_request; /** Incoming user request from the client */
static volatile bt_reply IS_REGISTERED;  /**  Is there a registered account on the devie? */
static uint8_t keybuf[1024];             /** Buffer to holds the Public Key data in key exchange step */
static size_t keylen;                    /** Length of the incoming public key in the key exchange step */

/* State function, implements each state */
static void state_err(const bt_buffer *param);
static void state_disconnect(const bt_buffer *param);
static void state_connected(const bt_buffer *param);
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
    STATE_CONNECTED,
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

/**
 * @brief State table untuk FSM
 * 
 * Implementasi FSM dilakukan dengan state table. Enum fsm_state digunakan untuk indeks array 
 * pada state table. Tiap elemen merupakan state terpisah, yang diimplementasi dalam fungsi 
 * sendiri.
 * 
 * @param param Parameter input ke FSM
 */
static void (*btFsm_state_table[])(const bt_buffer *param) =
    {
        state_err,
        state_disconnect,
        state_connected,
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

/* FSM interface functions */
static announceState _announceState = nullptr;
static generateNonce _generateNonce = nullptr;
static sendReply _sendReply = nullptr;
static writeBT _writeBT = nullptr;
static decryptBT _decryptBT = nullptr;
static storeCredential _storeCredential = nullptr;
static deleteStoredCredential _deleteStoredCredential = nullptr;
static loadPK _loadPK = nullptr;
static setCipherkey _setCipherkey = nullptr;
static writeBTRSA _writeBTRSA = nullptr;
static setAlarm _setAlarm = nullptr;
static setTimeout _setTimeout = nullptr;
static unpairBlacklist _unpairBlacklist = nullptr;
static setImmobilizer _setImmobilizer = nullptr;
static handleError _handleError = nullptr;
static disconnect _disconnect = nullptr;
static setDiscoverability _setDiscoverability = nullptr;
static customTransition _customTransition = nullptr;

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

/** 
 * @brief Mengubah state FSM
 * 
 * @param next_state State yang diinginkan
 * @note Terdapat delay >20 ms sebelum terjadi transisi ke state selanjutnya, untuk memisahkan output antar state 
 */
static void change_state(fsm_state next_state)
{
    delay(20);
    if (_announceState != nullptr)
        _announceState(next_state);
    _setTimeout(BT_DISABLE, 0); // Reset timeout
    current_state = next_state;
    onTransition(); // Panggil fungsi transisi
}

fsm_state get_current_state()
{
    return current_state;
}

unsigned int get_registration_status()
{
    return (unsigned int)IS_REGISTERED;
}

/**
 * @brief Menjalankan FSM
 * 
 * @param param Input ke FSM
 */
static void run_btFsm(const bt_buffer *param)
{
    btFsm_state_table[current_state](param);
}

int onInput(const bt_buffer *input)
{
    if (input->len > BT_BUF_LEN_BYTE)
        return BT_FAIL;
    else
    {
        run_btFsm(input);
        return BT_SUCCESS;
    }
}

int onEvent(bt_event event, const uint8_t *data, size_t len)
{
    if (len > BT_BUF_LEN_BYTE)
        return BT_FAIL;
    // Format benar
    bt_buffer evt;
    evt.event = event;
    evt.len = len;
    memcpy(&evt.data, data, len);
    run_btFsm(&evt);
    return BT_SUCCESS;
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
    if (_customTransition)
        _customTransition();
    else
    {
        bt_buffer transition;
        transition.event = EVENT_TRANSITION;
        run_btFsm(&transition);
    }
}

void onBypassDetection(int is_bypassed)
{
    bt_buffer bypass;
    bypass.event = EVENT_BYPASS_DETECTOR;
    bypass.len = 1;
    bypass.data[0] = (uint8_t)is_bypassed;
    run_btFsm(&bypass);
}

int init_btFsm(const fsm_interface *interface)
{
    init_bt_buffer(&nonce);
    init_bt_buffer(&USER_PIN);
    init_bt_buffer(&USER_ADDR);
    IS_REGISTERED = NACK;
    user_request = REQUEST_NOTHING;
    current_state = STATE_ERR;

    _announceState = interface->announceStateImp;
    if (_announceState == nullptr)
        return BT_FAIL;

    _generateNonce = interface->generateNonceImp;
    if (_generateNonce == nullptr)
        return BT_FAIL;

    _sendReply = interface->sendReplyImp;
    if (_sendReply == nullptr)
        return BT_FAIL;

    _writeBT = interface->writeBTImp;
    if (_writeBT == nullptr)
        return BT_FAIL;

    _decryptBT = interface->decryptBTImp;
    if (_decryptBT == nullptr)
        return BT_FAIL;

    _storeCredential = interface->storeCredentialImp;
    if (_storeCredential == nullptr)
        return BT_FAIL;

    _deleteStoredCredential = interface->deleteStoredCredentialImp;
    if (_deleteStoredCredential == nullptr)
        return BT_FAIL;

    _loadPK = interface->loadPKImp;
    if (_loadPK == nullptr)
        return BT_FAIL;

    _setCipherkey = interface->setCipherkeyImp;
    if (_setCipherkey == nullptr)
        return BT_FAIL;

    _writeBTRSA = interface->writeBTRSAImp;
    if (_writeBTRSA == nullptr)
        return BT_FAIL;

    _setAlarm = interface->setAlarmImp;
    if (_setAlarm == nullptr)
        return BT_FAIL;

    _setTimeout = interface->setTimeoutImp;
    if (_setTimeout == nullptr)
        return BT_FAIL;

    _unpairBlacklist = interface->unpairBlacklistImp;
    if (_unpairBlacklist == nullptr)
        return BT_FAIL;

    _setImmobilizer = interface->setImmobilizerImp;
    if (_setImmobilizer == nullptr)
        return BT_FAIL;

    _handleError = interface->handleErrorImp;
    if (_handleError == nullptr)
        return BT_FAIL;

    _disconnect = interface->disconnectImp;
    if (_disconnect == nullptr)
        return BT_FAIL;

    _setDiscoverability = interface->setDiscoverabilityImp;
    if (_setDiscoverability == nullptr)
        return BT_FAIL;

    _customTransition = interface->customTransitionImp;

    keylen = 0;
    for (int i = 0; i < 1024; i++)
    {
        keybuf[i] = 0;
    }

    current_state = STATE_DISCONNECT;
    _announceState(current_state);
    return BT_SUCCESS;
}

static void state_err(const bt_buffer *param)
{
    switch (param->event)
    {
    case EVENT_TRANSITION:
        _handleError();
        break;
    default: // TODO("Fix this")
        _handleError();
        break;
    }
}

static void state_disconnect(const bt_buffer *param)
{
    static int to_unpair = BT_ENABLE;
    switch (param->event)
    {
    case EVENT_TRANSITION:
    {
        init_bt_buffer(&client); // reset incoming client address
        int enable = BT_ENABLE;
        if (IS_REGISTERED == ACK)
            enable = BT_DISABLE;
        if (_setDiscoverability(enable) != BT_SUCCESS)
            change_state(STATE_ERR);
        break;
    }
    case EVENT_BT_CONNECT:
    {
        client.len = BT_ADDR_LEN;
        memcpy(&client.data, param->data, client.len); // save incoming client address
        if ((IS_REGISTERED == ACK) && (checkUserID(&client) != BT_SUCCESS))
        {
            to_unpair = BT_ENABLE;
            _disconnect();
        }
        else // no registered user yet, or the client is of registered address
            to_unpair = BT_DISABLE;
        // after this, wait for the client to send. This is done to sync the timing
        break;
    }
    case EVENT_BT_INPUT: // client address is already updated with the latest data
    {
        delay(20);
        if (to_unpair == BT_DISABLE) // client is registered
        {
            int ret = _sendReply(ACK);
            if (ret == BT_SUCCESS)
                change_state(STATE_CONNECTED);
            else 
                _disconnect();
        }
        else // inform the incoming client it's not registered yet, and disconnect
        {
            _sendReply(NACK);
            _disconnect();
        }
        break;
    }
    case EVENT_BT_DISCONNECT:
    {
        if (to_unpair == BT_ENABLE) // unpair
        {
            _unpairBlacklist(&client); // unpair
            to_unpair = BT_DISABLE;    // clear unpair flag
        }
        init_bt_buffer(&client); // reset incoming client address
        break;
    }
    case EVENT_BYPASS_DETECTOR:
    {
        if (param->data[0] == BT_ENABLE)
            _setAlarm(BT_ENABLE, BT_ALARM_DURATION_SEC);
        break;
    }
    default:
        break;
    }
}

static void state_connected(const bt_buffer *param)
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
                _sendReply(ACK);
                change_state(STATE_CHALLENGE);
                break;
            default: // REQUEST_NOTHING and other unimplemented feature (e.g. register)
                _sendReply(NACK);
                break;
            }
        }
        else // NACK
        {
            switch (user_request)
            {
            case REQUEST_REGISTER_PHONE:
                _sendReply(ACK);
                change_state(STATE_KEY_EXCHANGE);
                break;
            default: // REQUEST_NOTHING and other unimplemented feature (e.g. register)
                _sendReply(NACK);
                break;
            }
        }
        break;
    case EVENT_S_INPUT:
        _writeBT(param);
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    case EVENT_BYPASS_DETECTOR:
        if (param->data[0] == BT_ENABLE)
        {
            _sendReply(NACK);
            change_state(STATE_ALARM);
        }
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
        if (_generateNonce(&nonce) == BT_SUCCESS)
        {
            _writeBT(&nonce);
            change_state(STATE_VERIFICATION);
        }
        else // Fail to generate nonce, error
        {
            _sendReply(NACK);
            change_state(STATE_ERR);
        }
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    case EVENT_BYPASS_DETECTOR:
        if (param->data[0] == BT_ENABLE)
        {
            _sendReply(NACK);
            change_state(STATE_ALARM);
        }
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
        _setTimeout(BT_ENABLE, 5); // 5 s timeout for response
        break;
    case EVENT_BT_INPUT:
        bt_buffer response;
        init_bt_buffer(&response);
        if (_decryptBT(param, &response) == BT_SUCCESS)
        {
            // compare the response with the nonce
            if (compareBT(&nonce, &response) == BT_SUCCESS)
            {
                _sendReply(ACK);
                change_state(STATE_PIN);
            }
            else // cram mismatch
            {
                _sendReply(NACK);
                change_state(STATE_ALARM);
            }
        }
        else // error
        {
            _sendReply(ERR);
            change_state(STATE_ERR);
        }
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    case EVENT_TIMEOUT:
        _sendReply(NACK);
        change_state(STATE_CONNECTED);
        break;
    case EVENT_BYPASS_DETECTOR:
        if (param->data[0] == BT_ENABLE)
        {
            _sendReply(NACK);
            change_state(STATE_ALARM);
        }
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
        _setTimeout(BT_ENABLE, 60); // 1 minute to enter pin
        break;
    case EVENT_BT_INPUT:
        bt_buffer pin;
        init_bt_buffer(&pin);
        if (_decryptBT(param, &pin) == BT_SUCCESS)
        {
            // compare the response with the nonce
            if (checkUserPIN(&pin) == BT_SUCCESS)
            {
                _setAlarm(BT_DISABLE, 0);
                _sendReply(ACK);
                fsm_state next_state = STATE_CONNECTED;
                switch (user_request)
                {
                case REQUEST_UNLOCK:
                {
                    _setImmobilizer(BT_DISABLE);
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
                    next_state = STATE_CONNECTED;
                }
                change_state(next_state);
            }
            else
            {
                _sendReply(NACK);
                change_state(STATE_ALARM);
            }
        }
        else
        {
            _sendReply(ERR);
            change_state(STATE_ERR);
        }
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    case EVENT_TIMEOUT:
        _sendReply(NACK);
        change_state(STATE_CONNECTED);
        break;
    case EVENT_BYPASS_DETECTOR:
        if (param->data[0] == BT_ENABLE)
        {
            _sendReply(NACK);
            change_state(STATE_ALARM);
        }
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
        _setImmobilizer(BT_DISABLE);
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
            _setImmobilizer(BT_ENABLE);
            _sendReply(ACK);
            change_state(STATE_CONNECTED);
        }
        else
        {
            _sendReply(NACK);
        }
        break;
    }
    case EVENT_S_INPUT: // For debugging
    case EVENT_ENGINE:
    {
        if (param->data[0] != BT_ENABLE)
        {
            _setImmobilizer(BT_ENABLE);
            _sendReply(ACK);
            change_state(STATE_CONNECTED);
        }
        break;
    }
    case EVENT_BT_DISCONNECT:
    {
        change_state(STATE_UNLOCK_DISCONNECT);
        break;
    }
    case EVENT_BYPASS_DETECTOR:
    {
        if (param->data[0] == BT_ENABLE)
        {
            _sendReply(NACK);
            _setAlarm(BT_ENABLE, BT_ALARM_DURATION_SEC);
        }
        break;
    }
    default:
        break;
    }
}

static void state_unlock_disconnect(const bt_buffer *param)
{
    static int to_unpair = BT_ENABLE;
    switch (param->event)
    {
    case EVENT_TRANSITION:
        init_bt_buffer(&client); // clear incoming client address
        break;
    case EVENT_BT_CONNECT:
        client.len = BT_ADDR_LEN;
        memcpy(&client.data, param->data, client.len); // save incoming client address
        if ((IS_REGISTERED == ACK) && (checkUserID(&client) != BT_SUCCESS))
        {
            to_unpair = BT_ENABLE;
            _disconnect();
        }
        else // no registered user yet, or the client is of registered address
            to_unpair = BT_DISABLE;
        // after this, wait for the client to send. This is done to sync the timing
        break;
    case EVENT_BT_INPUT:             // client address is already updated with the latest data
        if (to_unpair == BT_DISABLE) // client is registered
        {
            _sendReply(ACK_UNL);
            change_state(STATE_UNLOCK);
        }
        else // inform the incoming client it's not registered yet, and disconnect
        {
            _sendReply(NACK);
            _disconnect();
        }
        break;
    case EVENT_BT_DISCONNECT:
        if (to_unpair == BT_ENABLE) // unpair
        {
            _unpairBlacklist(&client); // unpair
            to_unpair = BT_DISABLE;    // clear unpair flag
        }
        init_bt_buffer(&client); // reset incoming client address
        break;
    case EVENT_S_INPUT:
    case EVENT_ENGINE:
        change_state(STATE_DISCONNECT);
        break;
    case EVENT_BYPASS_DETECTOR:
        if (param->data[0] == BT_ENABLE)
            _setAlarm(BT_ENABLE, BT_ALARM_DURATION_SEC);
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
        _setTimeout(BT_ENABLE, 60); // 60 s timeout to enter new pin
        break;
    case EVENT_BT_INPUT:
        bt_buffer pin;
        init_bt_buffer(&pin);
        if (_decryptBT(param, &pin) == BT_SUCCESS)
        {
            if (_storeCredential(&pin, &client) == BT_SUCCESS)
            {
                if (load_user_cred((const uint8_t *)&pin.data, pin.len,
                                   (const uint8_t *)&client.data, client.len) == BT_SUCCESS)
                    _sendReply(ACK);
                else
                    _sendReply(NACK);
            }
            else
                _sendReply(NACK);
            change_state(STATE_CONNECTED);
        }
        else
        {
            _sendReply(ERR);
            change_state(STATE_ERR);
        }
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    case EVENT_TIMEOUT:
        _sendReply(NACK);
        change_state(STATE_CONNECTED);
        break;
    case EVENT_BYPASS_DETECTOR:
        if (param->data[0] == BT_ENABLE)
        {
            _sendReply(NACK);
            change_state(STATE_ALARM);
        }
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
        if (_deleteStoredCredential() == BT_SUCCESS)
        {
            init_bt_buffer(&USER_PIN);
            // init_bt_buffer(&USER_ADDR);
            IS_REGISTERED = NACK;
            _setDiscoverability(BT_ENABLE);
            _sendReply(ACK);
            // _disconnect();
        }
        else
            _sendReply(NACK);
        change_state(STATE_CONNECTED);
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    case EVENT_BYPASS_DETECTOR:
        if (param->data[0] == BT_ENABLE)
            change_state(STATE_ALARM);
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
        _setAlarm(BT_ENABLE, BT_ALARM_DURATION_SEC);
        change_state(STATE_CONNECTED);
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
        _setTimeout(BT_ENABLE, 60); // 60 s timeout for the phone to send it's public key
        break;
    case EVENT_BT_INPUT:
        memcpy(keybuf + keylen, param->data, param->len);
        keylen += param->len;
        // _announceState(STATE_KEY_EXCHANGE);
        break;
    case EVENT_BT_INPUT_END:
        // All PK bytes have been received, load the PK, generate the AES symkey, and send it over an encrypted channel
        keylen++;
        keybuf[keylen] = '\0';
        // Load PK
        if ((_loadPK(keybuf, keylen) == BT_SUCCESS) &&
            (_generateNonce(&nonce) == BT_SUCCESS))
        {
            if (_setCipherkey(&nonce) == BT_SUCCESS)
            {
                _writeBTRSA(&nonce);
                delay(20);
                _sendReply(ACK);
                change_state(STATE_NEW_PIN);
            }
            else
            {
                _sendReply(NACK);
                change_state(STATE_CONNECTED);
            }
        }
        else
        {
            _sendReply(NACK);
            change_state(STATE_CONNECTED);
        }
        break;
    case EVENT_TIMEOUT:
        _sendReply(NACK);
        change_state(STATE_CONNECTED);
        break;
    case EVENT_BT_DISCONNECT:
        change_state(STATE_DISCONNECT);
        break;
    case EVENT_BYPASS_DETECTOR:
        if (param->data[0] == BT_ENABLE)
            change_state(STATE_ALARM);
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
        // _setImmobilizer(BT_DISABLE); // debugging
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
        // _setImmobilizer(BT_ENABLE);
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

int raise_event(bt_buffer *buf, bt_event event, const uint8_t *data, size_t len)
{
    if (len > BT_BUF_LEN_BYTE || event == EVENT_TRANSITION)
    {
        buf->event = EVENT_NOTHING;
        return BT_FAIL;
    }
    else
    {
        buf->event = event;
        buf->len = len;
        if (buf->len > 0)
            memcpy(&buf->data, data, buf->len);
        return BT_SUCCESS;
    }
}

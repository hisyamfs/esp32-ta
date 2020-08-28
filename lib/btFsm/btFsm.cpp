#include "btFsm.h"

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
    int (*soundAlarmImp)(),
    void (*setImmobilizerImp)(int),
    int (*checkEngineOffImp)(),
    void (*handleErrorImp)())
{
    init_bt_buffer(&inbuf);
    init_bt_buffer(&outbuf);
    init_bt_buffer(&nonce);
    user_request = REQUEST_NOTHING;

    announceState = announceStateImp;
    readBTInput = readBTInputImp;
    readSInput = readSInputImp;
    generateNonce = generateNonceImp;
    sendReply = sendReplyImp;
    writeBT = writeBTImp;
    checkUserID = checkUserIDImp;
    checkUserPIN = checkUserPINImp;
    decryptBT = decryptBTImp;
    storePIN = storePINImp;
    soundAlarm = soundAlarmImp;
    setImmobilizer = setImmobilizerImp;
    checkEngineOff = checkEngineOffImp;
    handleError = handleErrorImp;

    current_state = STATE_DEF;
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
            if (compareBT(nonce, response) == BT_SUCCESS)
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
int compareBT(bt_buffer buf1, bt_buffer buf2)
{
    int no_mismatch = (buf1.len == buf2.len);
    for (int i = 0; i < BT_BLOCK_SIZE_BYTE && no_mismatch; i++)
    {
        no_mismatch = (buf1.data[i] == buf2.data[i]);
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

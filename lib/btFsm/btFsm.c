#include "btFsm.h"

void state_err()
{
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
        default: // No request and other unimplemented feature
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
                    disableImmobilizer();
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
}

void state_new_pin()
{
}

void state_alarm()
{
}

void state_register()
{
}

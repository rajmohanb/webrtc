/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
*                  Rajmohan Banavi (rajmohan@mindbricks.com)                   *
*                     MindBricks Confidential Proprietary.                     *
*                            All Rights Reserved.                              *
*                                                                              *
********************************************************************************
*                                                                              *
* This document contains information that is confidential and proprietary to   *
* MindBricks Technologies. No part of this document may be reproduced in any   *
* form whatsoever without prior written approval from MindBricks Technologies. *
*                                                                              *
*******************************************************************************/

#ifndef STUN_ENC_DEC_API__H
#define STUN_ENC_DEC_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include "stun_base.h"


#define STUN_MSG_AUTH_PASSWORD_LEN  128


typedef struct 
{
    uint32_t key_len;
    u_char key[STUN_MSG_AUTH_PASSWORD_LEN];
} stun_auth_params_t;

/**
 * Decode api. Decodes the given TLV message buffer into message structure and
 * returns a handle to the message. Further operations like set and get can 
 * be done on this returned h_msg.
 */
int32_t stun_msg_decode(u_char *buf, uint32_t len, 
                                    bool_t validate_fp, handle *tlv);

/**
 * Encode api. Converts the given message to TLV format and returns the TLV
 * message buffer that can be sent on the network to the peer.
 */
int32_t stun_msg_encode(handle tlv, 
            stun_auth_params_t *auth, u_char *buf, uint32_t *size);


int32_t stun_msg_print (handle stun_msg, u_char *buf, uint32_t buf_len);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

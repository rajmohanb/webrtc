/*******************************************************************************
*                                                                              *
*                 Copyright (C) 2014, MindBricks Technologies                  *
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

#ifndef DTLS_SRTP_INT__H
#define DTLS_SRTP_INT__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#define PC_DTLS_CERT_FILE  "mycert.pem"
#define PC_DTLS_KEY_FILE   "mycert.key"


/* TODO; need to revisit */    
#define PC_DTLS_CIPHERS     "ALL:NULL:eNULL:aNULL"


#define DTLS_RETX_TIMER_VAL 1000 /* milliseconds */


typedef enum {
    DTLS_SRTP_INVALID_STATE,
    DTLS_SRTP_INIT,
    DTLS_SRTP_HANDSHAKING,
    DTLS_SRTP_READY,
    DTLS_SRTP_MAX_STATE,
} dtls_srtp_state_t;



typedef struct {

    SSL_CTX *ctx;
    BIO *cert_bio;
    X509 *x;
    unsigned char md[EVP_MAX_MD_SIZE];

#if 0
    /* openssl params for dtls */
    BIO *bio;
    SSL *ssl; /* TODO; this should be moved to per session? */
#endif

    dtls_srtp_data_send_cb cb;
    dtls_srtp_incoming_app_data_cb app_cb;
    dtls_srtp_start_timer_cb timer_start_cb;
    dtls_srtp_stop_timer_cb timer_stop_cb;

} dtls_srtp_instance_t;


typedef struct {

    /* setup role as defined in rfc 4145 */
    dtls_setup_role_type_t role;

    /* connection specific parameters */
    SSL *ssl;

    /*source memory bio for this session */
    BIO *src_bio;

    /* sink memory bio for this session */
    BIO *sink_bio;

    /* opaque application handle */
    handle app_handle;

    /* state */
    dtls_srtp_state_t state;

    /* certificate digest type */
    dtls_key_type_t digest_type;

    /* peer certificate fingerprint */
    unsigned char peer_fp[EVP_MAX_MD_SIZE];
    uint32_t peer_fp_len;

    handle timer_id;

    /* 
     * Note; This is a minimal re-transmission implementation for now. To be
     * safe, we need to have retransmission implementation for multiple 
     * buffers, but as of now we have only one buffer. RFC 4347 talks of 
     * multiple flights during a handshake. To be taken care of in future.
     */

} dtls_srtp_session_t;


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

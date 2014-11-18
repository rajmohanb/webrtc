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

#ifndef DTLS_SRTP__H
#define DTLS_SRTP__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


typedef enum {
    DTLS_MD5,
    DTLS_SHA1,
    DTLS_SHA256,
} dtls_key_type_t;


typedef enum {

    DTLS_ROLE_MIN,
    DTLS_ACTIVE,
    DTLS_PASSIVE,
    DTLS_ACTPASS,
    DTLS_HOLDCONN,
    DTLS_ROLE_MAX,
} dtls_setup_role_type_t;


typedef void (*dtls_srtp_incoming_app_data_cb) (
        handle dtls, char *buf, int len, handle app_handle);
typedef int (*dtls_srtp_data_send_cb) (
        handle dtls, char *buf, int len, handle app_handle);
typedef handle (*dtls_srtp_start_timer_cb) (uint32_t duration, handle arg);
typedef int32_t (*dtls_srtp_stop_timer_cb) (handle timer_id);


mb_status_t dtls_srtp_init(dtls_srtp_data_send_cb cb, 
                           dtls_srtp_incoming_app_data_cb app_cb, 
                           dtls_srtp_start_timer_cb start_timer_cb, 
                           dtls_srtp_stop_timer_cb stop_timer_cb);


mb_status_t dtls_srtp_create_session(dtls_setup_role_type_t role, 
            dtls_key_type_t type, int sock, handle app_handle, handle *h_dtls);


mb_status_t dtls_srtp_session_do_handshake(handle h_dtls);


mb_status_t dtls_srtp_session_inject_data(handle h_dtls, 
                uint8_t *data, int len, int *is_handshake_done);


mb_status_t dtls_srtp_session_get_peer_fingerprint(
                    handle h_dtls, unsigned char *fp, uint32_t *fp_len);


mb_status_t dtls_srtp_session_get_keying_material(
                        handle h_dtls, unsigned char *keying_material);


mb_status_t dtls_srtp_inject_timer_event(handle timer_id, handle arg);


mb_status_t dtls_srtp_destroy_session(handle h_dtls);


mb_status_t dtls_srtp_deinit(void);


mb_status_t dtls_srtp_session_send_app_data(
                    handle h_dtls, uint8_t *data, int len);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

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

    DTLS_ROLE_MIN,
    DTLS_ACTIVE,
    DTLS_PASSIVE,
    DTLS_ACTPASS,
    DTLS_HOLDCONN,
    DTLS_ROLE_MAX,
} dtls_setup_role_type_t;


typedef int (*dtls_srtp_data_send_cb) (
        handle dtls, char *buf, int len, handle app_handle);


mb_status_t dtls_srtp_init(dtls_srtp_data_send_cb cb);


mb_status_t dtls_srtp_create_session(dtls_setup_role_type_t role, 
                            int sock, handle app_handle, handle *h_dtls);


mb_status_t dtls_srtp_session_do_handshake(handle h_dtls);


mb_status_t dtls_srtp_session_inject_data(handle h_dtls, 
                uint8_t *data, int len, int *is_handshake_done);


mb_status_t dtls_srtp_destroy_session(handle h_dtls);


mb_status_t dtls_srtp_deinit(void);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

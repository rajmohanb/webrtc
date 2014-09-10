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


mb_status_t dtls_srtp_init(void);


mb_status_t dtls_srtp_create_session(
                dtls_setup_role_type_t role, int sock, handle *h_dtls);


mb_status_t dtls_srtp_session_do_handshake(handle h_dtls);


mb_status_t dtls_srtp_destroy_session(handle h_dtls);


mb_status_t dtls_srtp_deinit(void);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

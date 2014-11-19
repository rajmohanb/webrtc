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


/* DCEP Message Types */
typedef enum {
    DCEP_RESERVED_0 = 0x00,
    DCEP_RESERVED_1 = 0x01,
    DCEP_DATA_CHANNEL_ACK = 0x02,
    DCEP_DATA_CHANNEL_OPEN = 0x03,
    DCEP_RESERVED_255 = 0xff,
} sctp_dcep_msg_type_t;


/* DCEP Channel Types */
typedef enum {
    DCEP_CHANNEL_RELIABLE = 0x00,
    DCEP_CHANNEL_PR_REXMIT = 0x01,
    DCEP_CHANNEL_PR_TIMED = 0x02,
    DCEP_CHANNEL_RELIABLE_UNORDERED = 0x80,
    DCEP_CHANNEL_PR_REXMIT_UNORDERED = 0x81,
    DCEP_CHANNEL_PR_TIMED_UNORDERED = 0x82,
} sctp_dcep_channel_type_t;


/* 
 * updated as of draft-ietf-rtcweb-data-channel-12 and 
 * draft-ietf-rtcweb-data-protocol-08 
 */
/* SCTP Payload Protocol IDentifiers (PPID) */
typedef enum {
    WEBRTC_DCEP = 50,
    WEBRTC_STRING = 51,
    WEBRTC_BINARY_PARTIAL = 52,
    WEBRTC_BINARY = 53,
    WEBRTC_STRING_PARTIAL = 54,
    WEBTRC_STRING_EMPTY = 56,
    WEBRTC_BINARY_EMPTY = 57,
} sctp_ppid_type_t;


typedef struct {
} sctp_dc_channel_t;


typedef struct {
} sctp_dc_stream_t;


typedef struct {

    struct socket *s;

    /* application blob */
    handle app_handle;
} sctp_dc_assoc_t;



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

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


/* max data channels per association */
#define SCTP_MAX_DATA_CHANNELS  8
/* max data streams in each direction per association */
#define SCTP_MAX_DATA_STREAMS   SCTP_MAX_DATA_CHANNELS


typedef enum {
    DCEP_STREAM_UNUSED,
    DCEP_STREAM_OPENING,
    DCEP_STREAM_OPEN,
    DCEP_STREAM_CLOSING,
    DCEP_STREAM_STATE_MAX,
} sctp_dcep_stream_state_t;


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


/* DATA_CHANNEL_OPEN message format */
typedef struct {
    uint8_t msg_type;
    uint8_t channel_type;
    uint16_t priority;
    uint32_t reliability_param;

    uint16_t label_len;
    uint16_t protocol_len;

    char *label;
    char *protocol;
} sctp_dc_open_msg_t;


/* DATA_CHANNEL_ACK message format */
typedef struct {
    uint8_t msg_type;
} sctp_dc_ack_msg_t;


typedef struct {

    /* reliable or unreliable */
    sctp_dcep_channel_type_t channel_type;
    uint32_t reliability_param; 

    /* in-order or out-of-order msg delivery */
    uint8_t is_in_order;

    /* priority */
    uint16_t priority;

    /* optional label */
    char *label;

    /* optional protocol */
    char *protocol;
} sctp_dc_channel_t;


typedef struct {

    sctp_dcep_stream_state_t state;
} sctp_dc_stream_t;


typedef struct {

    /* imp - 
     * In order to minimize the stream id lookup time, both the data channel 
     * and the associated stream are indexed by the same number. It is assumed 
     * that the stream ids will be numbered starting from 0 incrementally. That
     * is, index is the stream id.
     */
    sctp_dc_channel_t channels[SCTP_MAX_DATA_CHANNELS];

    sctp_dc_stream_t in_streams[SCTP_MAX_DATA_STREAMS];
    sctp_dc_stream_t out_streams[SCTP_MAX_DATA_STREAMS];

    struct socket *s;

    uint16_t is_dtls_client;

    /* application blob */
    handle app_handle;
} sctp_dc_assoc_t;


#ifdef MB_SCTP_DEBUG
void  mb_sctp_debug_packets(void *data, size_t datalen);
#endif


mb_status_t sctp_dcep_handle_message(sctp_dc_assoc_t *ctxt, 
                void *data, size_t datalen, struct sctp_rcvinfo *rcv);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

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

#ifndef RTCSIG__H
#define RTCSIG__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#define MAX_MESSAGE_QUEUE 32

struct rtcsig_lws_message {
	void *payload;
	size_t len;
};

enum webrtc_sig_protocols {

    WEBRTC_PROTO_DEFAULT,
    WEBRTC_PROTO_COUNT
};


typedef enum
{
    RTC_EVENT_SIGNIN = 0,
    RTC_EVENT_PEERS_LIST,
    RTC_EVENT_PEER_MEDIA,
    RTC_EVENT_PEER_ICE_CAND,
    RTC_EVENT_DEL_PEER,
    RTC_EVENT_NEW_PEER,
    RTC_EVENT_LOCAL_MEDIA,
    RTC_EVENT_LOCAL_ICE_CAND,
    RTC_EVENT_MAX,
} rtcsig_event_t;


typedef enum
{
    RTC_OFFLINE,
    RTC_SIGNING_IN,
    RTC_ONLINE,
    RTC_GOT_OFFER,
    RTC_LIVE,
    RTC_STATE_MAX,
} rtcsig_state_t;


typedef struct
{
    rtcsig_state_t state;
    struct libwebsocket *wsi;

    char *you;
    char *peer;

    int ringbuffer_head;
    int ringbuffer_tail;
    struct rtcsig_lws_message ringbuffer[MAX_MESSAGE_QUEUE];
} rtcsig_session_t;


typedef mb_status_t (*rtcsig_fsm_handler) 
                    (rtcsig_session_t *session, handle h_msg, handle h_param);


mb_status_t rtcsig_session_fsm_inject_msg(rtcsig_session_t *session, 
                        rtcsig_event_t event, handle h_msg, handle h_param);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

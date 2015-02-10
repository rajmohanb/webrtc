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

#ifndef RTC_MEDIA__H
#define RTC_MEDIA__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#define MB_LIVECAST_MAX_RECEIVERS   10

#define MB_FIR_REQ_FREQ_DURATION    15 /* seconds */


typedef enum {

    LIVECAST_INIT,
    LIVECAST_BC_OFFER_SENT,
    LIVECAST_BC_LIVE,

} livecast_state_t;


typedef struct {

    handle pc;
    int fd;
    char *id;
    bool is_broadcaster;

    bool intra_frame_requested;

    pc_local_media_desc_t local_desc;

    void *session;

    /* stats */
    uint32_t rtp_count;
    uint32_t rtcp_count;
    uint32_t data_count;
} rtc_participant_t;


typedef struct {

    livecast_state_t state;

    rtc_participant_t tx;
    sdp_session_t *tx_sdp;

    /* TODO; move these ssrc's into rtc_participant_t? */
    uint32_t tx_vid_ssrc1;
    uint32_t tx_vid_ssrc2;
    uint32_t tx_aud_ssrc;
    uint32_t tx_app_ssrc;

    uint32_t my_vid_ssrc1;
    uint32_t my_vid_ssrc2;
    uint32_t my_aud_ssrc;
    uint32_t my_app_ssrc;

    int cur_rx_count;
    rtc_participant_t rx[MB_LIVECAST_MAX_RECEIVERS];

} rtc_bcast_session_t;



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

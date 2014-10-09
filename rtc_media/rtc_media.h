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

typedef struct {

    handle pc;
    int fd;
    void *session;
    char *id;
} rtc_participant_t;

typedef struct {

    rtc_participant_t tx;

    int cur_rx_count;
    rtc_participant_t rx;
    //rtc_participant rx[MB_LIVECAST_MAX_RECEIVERS];

} rtc_bcast_session_t;



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

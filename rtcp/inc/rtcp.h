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

#ifndef RTCP__H
#define RTCP_H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

mb_status_t rtcp_parse_packet(char *buf, int len);

mb_status_t rtcp_send_rr(void);
mb_status_t rtcp_send_pli(void);
mb_status_t rtcp_send_fir(void);

mb_status_t rtcp_create_fir(unsigned char *buf, 
        uint32_t *len, uint32_t sender_ssrc, uint32_t target_ssrc);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

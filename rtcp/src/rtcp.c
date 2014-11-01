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

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>


#include <mb_types.h>

#include <rtcp_int.h>


mb_status_t rtcp_parse_sr(rtcp_pkt_t *pkt) {

    return MB_OK;
}

mb_status_t rtcp_parse_rr(rtcp_pkt_t *pkt) {

    return MB_OK;
}

mb_status_t rtcp_parse_sdes(rtcp_pkt_t *pkt) {

    return MB_OK;
}

mb_status_t rtcp_parse_bye(rtcp_pkt_t *pkt) {

    return MB_OK;
}

mb_status_t rtcp_parse_app(rtcp_pkt_t *pkt) {

    return MB_OK;
}

mb_status_t rtcp_parse_rtpfb(rtcp_pkt_t *pkt) {

    return MB_OK;
}

mb_status_t rtcp_parse_psfb(rtcp_pkt_t *pkt) {

    return MB_OK;
}



mb_status_t rtcp_parse_packet(char *buf, int len) {

    mb_status_t status;
    rtcp_pkt_t *pkt = (rtcp_pkt_t *)buf;

    switch(pkt->common.pt) {

        case RTCP_SR:
            status = rtcp_parse_sr(pkt);
            break;

        case RTCP_RR:
            status = rtcp_parse_rr(pkt);
            break;

        case RTCP_SDES:
            status = rtcp_parse_sdes(pkt);
            break;

        case RTCP_BYE:
            status = rtcp_parse_bye(pkt);
            break;

        case RTCP_APP:
            status = rtcp_parse_app(pkt);
            break;

        case RTCP_RTPFB:
            status = rtcp_parse_rtpfb(pkt);
            break;

        case RTCP_PSFB:
            status = rtcp_parse_psfb(pkt);
            break;

        default:
            break;
    }

    return MB_OK;
}


mb_status_t rtcp_send_rr(void) {

    return MB_OK;
}


mb_status_t rtcp_send_pli(void) {

    return MB_OK;
}


mb_status_t rtcp_create_fir(unsigned char *buf, 
        uint32_t *len, uint32_t sender_ssrc, uint32_t target_ssrc) {

    rtcp_fb_pkt_t *pkt = (rtcp_fb_pkt_t *)buf;

    pkt->r.fir.ssrc = htonl(target_ssrc);
    pkt->r.fir.seqno = 1;
    pkt->r.fir.res = 0;

    pkt->common.version = 2;
    pkt->common.p = 0;
    pkt->common.fmt = RTCP_PSFB_FIR;
    pkt->common.pt = RTCP_PSFB;
    pkt->common.length = 2 + (2*1);

    pkt->ssrc_sender = htonl(sender_ssrc);
    pkt->ssrc_src = 0;

    *len = sizeof(rtcp_fb_pkt_t);

    return MB_OK;
}


/******************************************************************************/

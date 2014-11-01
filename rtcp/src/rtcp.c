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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>


#include <mb_types.h>

#include <rtcp_int.h>


mb_status_t rtcp_parse_sr(uint8_t *buf, uint32_t *len) {

    uint16_t l;

    memcpy(&l, buf+2, sizeof(uint16_t));

    l = ntohs(l);
    *len = (l+1)*4;

    printf("Parse SR\n");
    return MB_OK;
}

mb_status_t rtcp_parse_rr(uint8_t *buf, uint32_t *len) {

    uint16_t l;
    //rtcp_pkt_t *pkt = (rtcp_pkt_t *)buf;

    memcpy(&l, buf+2, sizeof(uint16_t));

    l = ntohs(l);
    //printf("Parse RR of len %d and [%d]\n", pkt->common.length, l);

    *len = (l+1)*4;

    return MB_OK;
}

mb_status_t rtcp_parse_sdes(uint8_t *buf, uint32_t *len) {

    uint16_t l;

    memcpy(&l, buf+2, sizeof(uint16_t));

    l = ntohs(l);
    *len = (l+1)*4;

    //printf("Parse SDES\n");
    return MB_OK;
}

mb_status_t rtcp_parse_bye(uint8_t *buf, uint32_t *len) {

    uint16_t l;

    memcpy(&l, buf+2, sizeof(uint16_t));

    l = ntohs(l);
    *len = (l+1)*4;

    //printf("Parse BYE\n");
    return MB_OK;
}

mb_status_t rtcp_parse_app(uint8_t *buf, uint32_t *len) {

    uint16_t l;

    memcpy(&l, buf+2, sizeof(uint16_t));

    l = ntohs(l);
    *len = (l+1)*4;

    //printf("Parse APP\n");
    return MB_OK;
}

mb_status_t rtcp_parse_rtpfb(uint8_t *buf, uint32_t *len) {

    uint16_t l;

    memcpy(&l, buf+2, sizeof(uint16_t));

    l = ntohs(l);
    *len = (l+1)*4;

    //printf("Parse RTPFB\n");
    return MB_OK;
}

mb_status_t rtcp_parse_psfb(uint8_t *buf, uint32_t *len) {

    uint16_t l, i;

    memcpy(&l, buf+2, sizeof(uint16_t));

    l = ntohs(l);
    *len = (l+1)*4;

#if 0
    printf("Parse PSFB\n");
    for (i = 0; i < *len; i += 4, buf += 4)
        printf("%02X %02X %02X %02X\n", *buf, *(buf+1), *(buf+2), *(buf+3));
#endif
    return MB_OK;
}



mb_status_t rtcp_parse_packet(uint8_t *buf, uint32_t len) {

    mb_status_t status;
    rtcp_pkt_t *pkt = (rtcp_pkt_t *)buf;

    switch(pkt->common.pt) {

        case RTCP_SR:
            status = rtcp_parse_sr(buf, &len);
            break;

        case RTCP_RR:
            status = rtcp_parse_rr(buf, &len);
            break;

        case RTCP_SDES:
            status = rtcp_parse_sdes(buf, &len);
            break;

        case RTCP_BYE:
            status = rtcp_parse_bye(buf, &len);
            break;

        case RTCP_APP:
            status = rtcp_parse_app(buf, &len);
            break;

        case RTCP_RTPFB:
            status = rtcp_parse_rtpfb(buf, &len);
            break;

        case RTCP_PSFB:
            status = rtcp_parse_psfb(buf, &len);
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
    pkt->common.length = htons(2+(2*1));

    pkt->ssrc_sender = htonl(sender_ssrc);
    pkt->ssrc_src = 0;

    *len = sizeof(rtcp_fb_pkt_t);

    return MB_OK;
}


mb_status_t rtcp_rewrite_source_ssrc(
                uint8_t *buf, uint32_t buf_len, uint32_t ssrc) {

    uint32_t l, len = 0;
    mb_status_t status;
    rtcp_pkt_t *pkt;
    uint8_t *tmp = buf;

#if 0
    for (i = 0; i < 100; i+=4, tmp+=4) {
        printf("%02X %02X %02X %02X\n", *tmp, *(tmp+1), *(tmp+2), *(tmp+3));
    }
#endif

    while (len < buf_len) {

    tmp = buf+len;
    //printf("LOOP: len [%d] and buf_len [%d]\n", len, buf_len);
    //printf("%02X %02X %02X %02X\n", *tmp, *(tmp+1), *(tmp+2), *(tmp+3));

    pkt = (rtcp_pkt_t *)(buf+len);

    switch(pkt->common.pt) {

        case RTCP_SR:
            status = rtcp_parse_sr(buf+len, &l);
            break;

        case RTCP_RR:
            status = rtcp_parse_rr(buf+len, &l);
            break;

        case RTCP_SDES:
            status = rtcp_parse_sdes(buf+len, &l);
            break;

        case RTCP_BYE:
            status = rtcp_parse_bye(buf+len, &l);
            break;

        case RTCP_APP:
            status = rtcp_parse_app(buf+len, &l);
            break;

        case RTCP_RTPFB:
            status = rtcp_parse_rtpfb(buf+len, &l);
            break;

        case RTCP_PSFB:
            status = rtcp_parse_psfb(buf+len, &l);
            break;

        default:
            break;
    }

    //printf("Moving BUF by len %d\n", len);
    len += l;
    }

    //printf("********************************************\n");

    return MB_OK;
}



/******************************************************************************/

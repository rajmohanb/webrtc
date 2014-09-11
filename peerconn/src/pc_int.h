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

#ifndef PEERCONN_INT__H
#define PEERCONN_INT__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/



typedef enum {
    PC_BORN,
    PC_ICE_IN_PROGRESS,
    PC_DTLS_IN_PROGRESS,
    PC_ACTIVE,
    PC_DEAD,
    PC_STATE_MAX,
} pc_state_t;


typedef enum {
    PC_E_LOCAL_MEDIA_PARAMS,
    PC_E_PEER_MEDIA_PARAMS,
    PC_E_DATA,
    PC_E_TRICKLED_ICE_CAND,
    PC_E_ICE_COMPLETED,
    PC_E_ICE_FAILED,
    PC_EVENT_MAX,
} pc_event_t;


typedef struct {

    pc_state_t state;

    /* ice session params */
    handle ice_session;
    handle media;

#if 0
    pc_ice_media_host_comp_t host_cands[PC_ICE_MAX_HOST_CANDS];
#endif

    /* dtls session */
    handle dtls;

    /* sock fd */
    int sock_fd;

    /* peer sock addr */
    struct sockaddr_in peer_addr;
} pc_ctxt_t;



typedef struct {
    handle ice_instance;
} pc_instance_t;


typedef mb_status_t (*pc_fsm_handler) 
                    (pc_ctxt_t *ctxt, handle h_msg, handle param);

mb_status_t pc_fsm_inject_msg(pc_ctxt_t *ctxt, 
            pc_event_t event, handle h_msg, handle param);


/* utilities */

mb_status_t pc_utils_make_udp_transport_connected(pc_ctxt_t *ctxt);
mb_status_t pc_utils_process_ice_msg(pc_ctxt_t *ctxt, pc_rcvd_data_t *msg);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

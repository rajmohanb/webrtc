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

/* openssl */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* sdp */ 
#include <sdp.h>

/* ice */
#include <stun_base.h>
#include <ice_api.h>

/* srtp */
#include <srtp/err.h>
#include <srtp/srtp.h>

#include <mb_types.h>

/* dtls-srtp */
#include <dtls_srtp.h>

#include <pc.h>
#include <pc_int.h>


extern pc_instance_t g_pc;

static mb_status_t pc_ignore_msg (
                    pc_ctxt_t *ctxt, handle h_msg, handle param);
static mb_status_t pc_init_ice (pc_ctxt_t *ctxt, handle msg, handle param);
static mb_status_t pc_peer_ice (pc_ctxt_t *ctxt, handle msg, handle param);
static mb_status_t pc_peer_media (
                    pc_ctxt_t *ctxt, handle h_msg, handle param);
static mb_status_t pc_data (pc_ctxt_t *ctxt, handle msg, handle param);
//static mb_status_t pc_init_checks (pc_ctxt_t *ctxt, handle msg, handle param);
static mb_status_t pc_ice_failed (pc_ctxt_t *ctxt, handle msg, handle param);
static mb_status_t pc_init_dtls (pc_ctxt_t *ctxt, handle msg, handle param);


static char *pc_states[] = {
    "PC_BORN",
    "PC_ICE_IN_PROGRESS",
    "PC_DTLS_IN_PROGRESS",
    "PC_ACTIVE",
    "PC_DEAD",
};

static pc_fsm_handler 
    pc_session_fsm[PC_STATE_MAX][PC_EVENT_MAX] =
{
    /* PC_BORN */
    {
        pc_init_ice,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
    },
    /* PC_ICE_IN_PROGRESS */
    {
        pc_ignore_msg,
        pc_peer_media,
        pc_data,
        pc_peer_ice,
        pc_init_dtls,
        pc_ice_failed,
    },
    /* PC_DTLS_IN_PROGRESS */
    {
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
    },
    /* PC_ACTIVE */
    {
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
    },
    /* PC_DEAD */
    {
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
        pc_ignore_msg,
    },
};



static mb_status_t pc_init_ice (pc_ctxt_t *ctxt, handle msg, handle param) {

    int32_t i, ice_status;
    ice_api_media_stream_t lmedia;
    pc_local_media_desc_t *desc = (pc_local_media_desc_t *)msg;

    strncpy(lmedia.ice_ufrag, desc->ice_ufrag, ICE_MAX_UFRAG_LEN);
    strncpy(lmedia.ice_pwd, desc->ice_pwd, ICE_MAX_PWD_LEN);

    lmedia.num_comp = desc->num_comps;

    for (i = 0; i < desc->num_comps; i++) {

        memcpy(&lmedia.host_cands[i], 
                &desc->host_cands[i], sizeof(ice_media_host_comp_t));

#if 0
        /* make a copy in pc context for later use */
        memcpy(&ctxt->host_cands[i], 
                &desc->host_cands[i], sizeof(ice_media_host_comp_t));
#endif
    }

    /* 
     * TODO; make a copy of the socket descriptor for later use with dtls 
     * and srtp. Though this will work now only with chrome because of 
     * BUNDLE and rtcp mux. However, for working with other scenarios, there 
     * needs to be a way to differentiate the sockets.
     */
    ctxt->sock_fd = (int) lmedia.host_cands[0].transport_param;

    ice_status = ice_session_add_media_stream(
            g_pc.ice_instance, ctxt->ice_session, &lmedia, &ctxt->media);
    if (ice_status != STUN_OK) {
        MB_LOG(MBLOG_ERROR, 
                "ICE adding of media returned error %d\n", ice_status);
        return MB_INT_ERROR;
    }

    /* initiate ice gathering */
    ice_status = ice_session_gather_candidates(
            g_pc.ice_instance, ctxt->ice_session, true); 
    if (ice_status != STUN_OK) {
        MB_LOG(MBLOG_ERROR, "ICE gathering returned error %d\n", ice_status);
        return MB_INT_ERROR;
    }

    ctxt->state = PC_ICE_IN_PROGRESS;

    return MB_OK;
}


static mb_status_t pc_peer_ice (pc_ctxt_t *ctxt, handle msg, handle param) {

    int32_t ice_status;
    pc_ice_cand_t *trickle = (pc_ice_cand_t *) msg;

    ice_status = ice_session_set_peer_trickle_candidate(
            g_pc.ice_instance, ctxt->ice_session, ctxt->media, trickle);
    if (ice_status != STUN_OK) {
        MB_LOG(MBLOG_ERROR, "Processing of Peer "\
                "Trickled ICE candidate returned error %d\n", ice_status);
        return MB_INT_ERROR;
    }

    return MB_OK;
}


static mb_status_t pc_peer_media (pc_ctxt_t *ctxt, handle msg, handle param) {

    int32_t ice_status;
    ice_session_params_t peer_params;
    pc_media_desc_t *peer_desc = (pc_media_desc_t *)msg;

    memset(&peer_params, 0, sizeof(ice_session_params_t));

    /* set remote media params to the ice session */
    peer_params.ice_mode = ICE_MODE_FULL; /* TODO; hardcoded */
    peer_params.num_media = 1;            /* TODO; hardcoded */


    memcpy(peer_params.media[0].ice_ufrag, 
            peer_desc->ice_ufrag, PC_ICE_MAX_UFRAG_LEN);
    memcpy(peer_params.media[0].ice_pwd, 
            peer_desc->ice_pwd, PC_ICE_MAX_PWD_LEN);
    /* ignoring 'ice-options' for now since ice stack doesn't understand it */

    /*
     * Hack!
     * This might work only for chrome and probably opera but we assume here
     * that BUNDLE is being used to send media for all media on only one
     * transport. So media is always 1.
     * Further, it is assumed that rtcp-mux is being used to send both rtp
     * and rtcp on the same transport. So number of components in a media is 1.
     */
    peer_params.media[0].num_comps = 1;

    peer_params.media[0].h_media = ctxt->media;

    ice_status = ice_session_set_peer_session_params(
            g_pc.ice_instance, ctxt->ice_session, &peer_params);
    if (ice_status != STUN_OK) {
        MB_LOG(MBLOG_ERROR, "ICE setting remote "\
                "media params returned error %d\n", ice_status);
        return MB_INT_ERROR;
    }

    MB_LOG(LOG_SEV_ERROR, "[PEERCONN SESSION] Handle peer session desc");

    return MB_OK;
}


static mb_status_t pc_data (pc_ctxt_t *ctxt, handle msg, handle param) {

    mb_status_t status;

    /* TODO; identify the type of message and ignore if not stun or dtls? */

    status = pc_utils_process_ice_msg(ctxt, (pc_rcvd_data_t *)msg);

    return status;
}


#if 0
static mb_status_t pc_init_checks (pc_ctxt_t *ctxt, handle msg, handle param) {

    int32_t ice_status;

    ice_status = ice_session_form_check_lists(ice_instance, ctxt->ice_session);
    if (ice_status != STUN_OK) {

        MB_LOG(MBLOG_ERROR, 
                "ice_session_form_check_lists() returned error: %d\n", ice_status);
        ctxt->state = PC_DEAD;
        return MB_TERMINATED;
    }

    ice_status = 
        ice_session_start_connectivity_checks(ice_instance, ctxt->ice_session);
    if (ice_status != STUN_OK) {

        MB_LOG(MBLOG_ERROR, "ice_session_start_connectivity_checks() "\
                                            "returned error: %d\n", ice_status);
        ctxt->state = PC_DEAD;
        return MB_INT_ERROR;
    }

    return MB_OK;
}
#endif

static mb_status_t pc_init_dtls (pc_ctxt_t *ctxt, handle msg, handle param) {

    mb_status_t status;

    status = pc_utils_make_udp_transport_connected(ctxt);
    if (status != MB_OK) {
        fprintf(stderr, 
                "Error while making UDP socket connected: %d\n", status);
        return status;
    }

    /* initiate dlts srtp session */
    status = dtls_srtp_create_session(DTLS_ACTIVE, ctxt->sock_fd, &ctxt->dtls);
    if (status != MB_OK) {
        fprintf(stderr, "Error while creating DTLS-SRTP session: %d\n", status);
        return status;
    }

    status = dtls_srtp_session_do_handshake(ctxt->dtls);
    if (status != MB_OK) {
        fprintf(stderr, 
                "Error while performing DTLS-SRTP handshake: %d\n", status);
        return status;
    }

    fprintf(stderr, "DTLS Handshake initiated\n");

    return status;
}

static mb_status_t pc_ice_failed (pc_ctxt_t *ctxt, handle msg, handle param) {

    /* TODO; tear down ice session */

    ctxt->state = PC_DEAD;

    return MB_OK;
}

static mb_status_t pc_ignore_msg (pc_ctxt_t *ctxt, handle h_msg, handle param) {

    ICE_LOG(LOG_SEV_ERROR, "[PEERCONN SESSION] Event ignored");
    return MB_OK;
}


mb_status_t pc_fsm_inject_msg(pc_ctxt_t *ctxt, 
            pc_event_t event, handle h_msg, handle param)
{
    int32_t status;
    pc_fsm_handler handler;
    pc_state_t cur_state;

    cur_state = ctxt->state;
    handler = pc_session_fsm[cur_state][event];

    if (!handler) return MB_INVALID_PARAMS;

    status = handler(ctxt, h_msg, param);

    if (cur_state != ctxt->state)
    {
        ICE_LOG(MBLOG_ERROR, 
                "PC SESSION State changed to [%s]\n", pc_states[ctxt->state]);
    }

    return status;
}





/******************************************************************************/

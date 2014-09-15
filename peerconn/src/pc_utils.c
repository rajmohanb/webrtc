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

/* ice */
#include <stun_base.h>
#include <stun_enc_dec_api.h>
#include <ice_api.h>

/* srtp */
#include <srtp/err.h>
#include <srtp/srtp.h>

#include <mb_types.h>

/* dtls */
#include <dtls_srtp.h>

#include <pc.h>
#include <pc_int.h>


extern pc_instance_t g_pc;


mb_status_t pc_utils_process_ice_msg(pc_ctxt_t *ctxt, pc_rcvd_data_t *msg) {

    handle stun_msg;
    ice_rx_stun_pkt_t pkt;
    int32_t ice_status;

    ice_status = ice_instance_verify_valid_stun_packet(msg->buf, msg->buf_len);
    if(ice_status == STUN_MSG_NOT) {
        fprintf(stderr, "******** Non-STUN packet received *********\n");
        return MB_INVALID_PARAMS;
    }

    ice_status = stun_msg_decode(msg->buf, msg->buf_len, false, &stun_msg); 
    if (ice_status != STUN_OK) {

        MB_LOG(MBLOG_ERROR, 
                "stun_msg_decode() returned error: %d\n", ice_status);
        return MB_INT_ERROR;
    }

    /* TODO; hard code here of the received from address */
    pkt.h_msg = stun_msg;
    pkt.transport_param = msg->transport_param;
    memcpy(&pkt.src, &msg->src, sizeof(mb_inet_addr_t));

    ice_status = ice_session_inject_received_msg(
            g_pc.ice_instance, ctxt->ice_session, &pkt);
    if (ice_status != STUN_OK) {

        printf("ice_session_inject_received_msg() "\
                            "returned error: %d\n", ice_status);
        return MB_INT_ERROR;
    }

    return MB_OK;
}



mb_status_t pc_utils_make_udp_transport_connected(pc_ctxt_t *ctxt) {

    int ret;
    int32_t ice_status;
    stun_inet_addr_t *peer;
    //struct sockaddr_in dest;
    ice_session_valid_pairs_t selected_pair;

    memset(&ctxt->peer_addr, 0, sizeof(struct sockaddr_in));

    /* 
     * get the ice nominated pairs, so that we can connect the udp socket to 
     * the nominated dest address. This is required for dtls datagram BIO 
     * during handshake and I/O communication.
     */
    /* TODO; 
     * This will work for only one media and one nominated pair per peer 
     * connection context. Scaling to support multiple media and components?
     */
    ice_status = ice_session_get_nominated_pairs(
            g_pc.ice_instance, ctxt->ice_session, &selected_pair);
    if (ice_status != STUN_OK) {
        fprintf(stderr, "Error while retrieving ICE nominated candidate "\
                "pair from ICE library. Returned ice status: %d\n", ice_status);
        return MB_INT_ERROR;
    }

    /* TODO; as above */
    peer = &selected_pair.media_list[0].pairs[0].peer;
    printf("Nominated Destination pair: %s and %d\n", peer->ip_addr, peer->port);

    ctxt->peer_addr.sin_family = AF_INET; /* TODO; hard code */
    ctxt->peer_addr.sin_port = htons(peer->port);
    ret  = inet_pton(AF_INET, (char *)peer->ip_addr, &ctxt->peer_addr.sin_addr);
    if (ret != 1) {
        perror("inet_pton:");
        ICE_LOG (LOG_SEV_ERROR, 
                "%s: inet_pton() failed %d\n", peer->ip_addr, ret);
        return MB_INT_ERROR;
    }

#if 0
    if (connect(ctxt->sock_fd, (struct sockaddr *)&ctxt->peer_addr, 
                                        sizeof(struct sockaddr_in)) == -1) {
        perror("Connect ");
        fprintf(stderr, "Making the UDP socket connected failed\n");
        return MB_INT_ERROR;
    }
#endif

    return MB_OK;
}



mb_status_t pc_utils_verify_peer_fingerprint(pc_ctxt_t *ctxt) {

    mb_status_t status;
    uint32_t i, len = EVP_MAX_MD_SIZE;
    unsigned char peer_fp[EVP_MAX_MD_SIZE] = {0};
    char *ptr, fingerprint[MAX_DTLS_FINGERPRINT_KEY_LEN] = {0};

    ptr = fingerprint;

    status = dtls_srtp_session_get_peer_fingerprint(ctxt->dtls, peer_fp, &len);
    if (status != MB_OK) {
        fprintf(stderr, 
                "ERROR: while retrieving DTLS peer certificate fingerprint\n");
        return status;
    }

    /* string compare if failing! need to format the string for comparision */
    for (i = 0; i < len; i++) {
        ptr += sprintf(ptr, "%.2X:", peer_fp[i]);
    }
    ptr--; *ptr = 0;

    /* 
     * compare the peer cert fingerprint retrieved from the peer 
     * certificate against the one received in the signaling.
     * TODO; should I use memcmp() because of unsigned char? but it's all ascii
     */
    printf("FP1: %s\n", ctxt->peer_cert_fp);
    printf("FP2: %s\n", fingerprint);
    if (strcasecmp((char *)ctxt->peer_cert_fp, (char *)fingerprint) != 0) {

        /* no match! */
        fprintf(stderr, "Matching of peer certificate fingerprint received "\
                "from the peer via signaling and the one received over DTLS "\
                "failed. Intruder alert?\n");
        ctxt->state = PC_DEAD;
        /* TODO; How do we notify the app to terminate this pc session? */
        return MB_VALIDATON_FAIL;
    }

    fprintf(stderr, "DTLS certificates matched\n");

    ctxt->state = PC_ACTIVE;

    return MB_OK;
}



/******************************************************************************/

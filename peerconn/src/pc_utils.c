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

/* data channel */
#include <sctp.h>

/* dtls */
#include <dtls_srtp.h>

#include <pc.h>
#include <pc_int.h>


extern pc_instance_t g_pc;
extern pc_ic_media_data_cb pc_media_cb;


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

    /* store the local and remote ports for later use for data channel */
    ctxt->local_port = selected_pair.media_list[0].pairs[0].local.port;
    ctxt->peer_port = peer->port;

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
    unsigned char in_policy_key[SRTP_MASTER_KEY_LEN];
    unsigned char ob_policy_key[SRTP_MASTER_KEY_LEN];
    err_status_t err;

    ptr = fingerprint;

    status = dtls_srtp_session_get_peer_fingerprint(ctxt->dtls, peer_fp, &len);
    if (status != MB_OK) {
        fprintf(stderr, 
                "ERROR: while retrieving DTLS peer certificate fingerprint\n");
        return status;
    }

    /* string compare if failing! need to format the string for comparision */
    for (i = 0; i < len; i++) {
        ptr += sprintf(ptr, "%02X:", peer_fp[i]);
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

    status = dtls_srtp_session_get_keying_material(
                                        ctxt->dtls, ctxt->keying_material);
    if (status != MB_OK) {
        fprintf(stderr, "ERROR: while retrieving "\
                "SRTP Keying Material from DTLS session\n");
        return status;
    }

    if (ctxt->my_dtls_role == PC_DTLS_ACTIVE) {

        /* client */
        ctxt->local_key = ctxt->keying_material;
        ctxt->peer_key = ctxt->local_key + SRTP_KEY_LEN;
        ctxt->local_salt = ctxt->peer_key + SRTP_KEY_LEN;
        ctxt->peer_salt = ctxt->local_salt + SRTP_SALT_LEN;
    } else if (ctxt->my_dtls_role == PC_DTLS_PASSIVE) {

        /* server */
        ctxt->peer_key = ctxt->keying_material;
        ctxt->local_key = ctxt->local_key + SRTP_KEY_LEN;
        ctxt->peer_salt = ctxt->peer_key + SRTP_KEY_LEN;
        ctxt->local_salt = ctxt->local_salt + SRTP_SALT_LEN;
    } else {
        fprintf(stderr, "Unknown DTLS ROLE: %d\n", ctxt->my_dtls_role);
        return MB_INT_ERROR;
    }

    memset(&in_policy_key, 0, sizeof(in_policy_key));
    memset(&ob_policy_key, 0, sizeof(ob_policy_key));

    /* setup srtp session(s) */
    crypto_policy_set_rtp_default(&ctxt->in_policy.rtp);
    crypto_policy_set_rtcp_default(&ctxt->in_policy.rtcp);

    crypto_policy_set_rtp_default(&ctxt->ob_policy.rtp);
    crypto_policy_set_rtcp_default(&ctxt->ob_policy.rtcp);

    /* incoming policy */
    ctxt->in_policy.ssrc.type = ssrc_any_inbound;
    ctxt->in_policy.key = in_policy_key;
    memcpy(ctxt->in_policy.key, ctxt->peer_key, SRTP_KEY_LEN);
    memcpy((ctxt->in_policy.key+SRTP_KEY_LEN), ctxt->peer_salt, SRTP_SALT_LEN);

    /* outgoing policy */
    ctxt->ob_policy.ssrc.type = ssrc_any_outbound;
    ctxt->ob_policy.key = ob_policy_key;
    memcpy(ctxt->ob_policy.key, ctxt->local_key, SRTP_KEY_LEN);
    memcpy((ctxt->ob_policy.key+SRTP_KEY_LEN), ctxt->local_salt, SRTP_SALT_LEN);

    if (ctxt->dir == PC_MEDIA_RECVONLY) {
        fprintf(stderr, "PEERCONN MEDIA DIRECTION: RECVONLY\n");
    } else if (ctxt->dir == PC_MEDIA_SENDONLY) {
        fprintf(stderr, "PEERCONN MEDIA DIRECTION: SENDONLY\n");
    } else {
        fprintf(stderr, 
                "We do not support this media direction %d. TODO\n", ctxt->dir);
        return MB_NOT_SUPPORTED;
    }

    ctxt->in_policy.window_size = 1024;  /* optimal value? */
    ctxt->in_policy.allow_repeat_tx = 0; /* TODO; Chrome sets it to 1? */
    ctxt->in_policy.next = NULL;

    err = srtp_create(&ctxt->srtp_in, &ctxt->in_policy);
    if (err != err_status_ok) {
        fprintf(stderr, "Creation of inbound srtp session failed\n");
        return MB_INT_ERROR;
    }

    /* now for outgoing */
    ctxt->ob_policy.window_size = 1024;  /* optimal value? */
    ctxt->ob_policy.allow_repeat_tx = 0; /* TODO; Chrome sets it to 1? */
    ctxt->ob_policy.next = NULL;

    err = srtp_create(&ctxt->srtp_ob, &ctxt->ob_policy);
    if (err != err_status_ok) {
        fprintf(stderr, "Creation of inbound srtp session failed\n");
        return MB_INT_ERROR;
    }

    /* data channel establishment happens after peerconn is done */
    status = dc_sctp_create_association(
                    5000, 5000, ctxt, &ctxt->dc);
                    //ctxt->local_port, ctxt->peer_port, ctxt, &ctxt->dc);
    if (status != MB_OK) {
        fprintf(stderr, "Error [%d] while creating data "\
                "connection. Hence peerconn session terminating\n", status);
        ctxt->state = PC_DEAD;
        return status;
    }

    ctxt->state = PC_DC_IN_PROGRESS;

    fprintf(stderr, "PC Session moved to PC_DC_IN_PROGRESS state\n");

    return MB_OK;

    /* TODO: error handling */
}



mb_status_t pc_utils_process_srtp_packet(
                    pc_ctxt_t *ctxt, uint8_t *buf, uint32_t len) {

    err_status_t err;
    int rtp_len = len;
    uint32_t pt;

    //fprintf(stderr, "Before Unprotect: buf %p and len %d\n", buf, rtp_len);
    pt = (uint32_t) *(buf+1); 
    //fprintf(stderr, "Payload Type: %d\n", pt);

    if ((pt > 191) && (pt < 210)) {

        err = srtp_unprotect_rtcp(ctxt->srtp_in, buf, &rtp_len);
        if (err != err_status_ok) {
            fprintf(stderr, "SRTCP unprotect() returned error %d. "\
                    "Starting byte %d. Payload type byte: %d Context: %p\n", 
                    err, *buf, pt, ctxt);
            return MB_INVALID_PARAMS;
        }

        //fprintf(stderr, "RX RTCP Payload Type: %d Len: %d\n", pt, rtp_len);
    } else {

        err = srtp_unprotect(ctxt->srtp_in, buf, &rtp_len);
        if (err != err_status_ok) {
            fprintf(stderr, "SRTP unprotect() returned error %d. "\
                    "Starting byte %d. Is it RTCP?\n", err, *buf);
            return MB_INVALID_PARAMS;
        }
    }

    //fprintf(stderr, "After Unprotect: buf %p and len %d\n", buf, rtp_len);

    /* hand over the clear rtp packets to application */
    pc_media_cb(ctxt, ctxt->app_blob, buf, (uint32_t)rtp_len);

    return MB_OK;
}



mb_status_t pc_utils_send_media_to_peer(
                pc_ctxt_t *ctxt, uint8_t *media, uint32_t len) {

    err_status_t err;
    int b, buf_len = len;
    char buf[2048] = {0};
    uint32_t pt;

    /* 
     * determine if its rtp or rtcp based on payload type. 
     * can't application pass the type?
     */
    pt = (uint32_t) *(media+1); 

    memcpy(buf, media, len);
    //printf("Copied media data of len %d to stack mem\n", len);
    
    //fprintf(stderr, "TX Payload Type: %d Len: %d\n", pt, len);
    if ((pt > 191) && (pt < 210)) {

        err = srtp_protect_rtcp(ctxt->srtp_ob, buf, &buf_len);
        if (err != err_status_ok) {
            fprintf(stderr, "SRTP protect() for RTCP returned error %d\n", err);
            return MB_INVALID_PARAMS;
        }
        //fprintf(stderr, "SRTP protected RTCP packet Type: %d Len: %d\n", pt, buf_len);
    } else {

        err = srtp_protect(ctxt->srtp_ob, buf, &buf_len);
        if (err != err_status_ok) {
            fprintf(stderr, "SRTP protect() for RTP returned error %d\n", err);
            return MB_INVALID_PARAMS;
        }
    }

    b = pc_send_dtls_srtp_data(NULL, buf, buf_len, ctxt);
    if (b <= 0) {
        fprintf(stderr, "Sending of media data to receiver node failed\n");
        return MB_INT_ERROR;
    }

    return MB_OK;
}



/******************************************************************************/

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


/* defined in rfc 3711 */
#define SRTP_KEY_LEN    16
#define SRTP_SALT_LEN   14


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

    /* application blob */
    handle app_blob;

    /* ice session params */
    handle ice_session;
    handle media;

    pc_media_dir_t dir;

#if 0
    pc_ice_media_host_comp_t host_cands[PC_ICE_MAX_HOST_CANDS];
#endif

    /* dtls session */
    handle dtls;
    pc_dtls_role_t my_dtls_role;

    /* dtls parameters */
    unsigned char peer_cert_fp[MAX_DTLS_FINGERPRINT_KEY_LEN];
    pc_dtls_key_type_t dtls_key_type;
    pc_dtls_role_t peer_dtls_role;

    /* sock fd */
    int sock_fd;

    /* peer sock addr */
    struct sockaddr_in peer_addr;

    /* srtp session */
    srtp_t srtp_in;
    srtp_t srtp_ob;

    /* srtp keying material from dtls (client key, salt & server key, salt */
    unsigned char keying_material[SRTP_MASTER_KEY_LEN * 2];
    unsigned char *local_key, *local_salt;
    unsigned char *peer_key, *peer_salt;

    /* TODO; 
     * Chrome only as of now, assumption is BUNDLE is used and rtcp-mux is used
     */
    srtp_policy_t in_policy;
    srtp_policy_t ob_policy;
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

mb_status_t pc_utils_verify_peer_fingerprint(pc_ctxt_t *ctxt);

mb_status_t pc_utils_process_srtp_packet(
                    pc_ctxt_t *ctxt, uint8_t *buf, uint32_t len);

mb_status_t pc_utils_send_media_to_peer(
                pc_ctxt_t *ctxt, uint8_t *media, uint32_t len);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

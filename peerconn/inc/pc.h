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

#ifndef PEERCONN__H
#define PEERCONN_H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#define STUN_SERVER_IP      "74.125.200.127"
#define STUN_SERVER_PORT    19302
//#define STUN_SERVER_IP      "50.116.13.218"
//#define STUN_SERVER_PORT    3478
#define TURN_SERVER_IP      "50.116.13.218"
#define TURN_SERVER_PORT    3478

/* DTLS defines */
#define MAX_DTLS_FINGERPRINT_KEY_LEN    128 

/* ICE defines */
#define PC_ICE_MAX_UFRAG_LEN    256
#define PC_ICE_MAX_PWD_LEN      256
#define PC_ICE_OPTIONS_LEN      64

#define PC_ICE_MAX_HOST_CANDS   1

#define ICE_VENDOR_NAME         "MindBricks"
#define ICE_VENDOR_NAME_LEN     10

#define PC_TIMER_PORT           12345 

#define PC_ICE_TIMER            1
#define PC_DTLS_TIMER           2

typedef struct
{
    void *timer_id;
    void *arg;
    uint8_t timer_type;
} pc_timer_event_t;


typedef enum {
    PC_MD5,
    PC_SHA1,
    PC_SHA256,
} pc_dtls_key_type_t;


typedef enum {
    PC_DTLS_ROLE_MIN,
    PC_DTLS_ACTIVE,
    PC_DTLS_PASSIVE,
    PC_DTLS_ACTPASS,
    PC_DTLS_HOLDCONN,
    PC_DTLS_ROLE_MAX,
} pc_dtls_role_t;


typedef enum {
    PC_MEDIA_SENDONLY,
    PC_MEDIA_RECVONLY,
    PC_MEDIA_SENDRECV,
    PC_MEDIA_NONE,
} pc_media_dir_t;


typedef struct
{
    /** host candidate transport details */
    mb_inet_addr_t addr;
    mb_transport_protocol_type_t protocol;

    /** 
     * local preference for this candidate as defined in ICE RFC 4.1.2.1. 
     * It must be an integer from 0 to 65535 inclusive. If the device is 
     * multi-homed only, then set the value as per preference. Otherwise, 
     * if a single IP address, then set it to 65535.
     */
    uint32_t local_pref;

    /** component id */
    uint32_t comp_id;

    /** application transport handle */
    handle transport_param;

} pc_ice_media_host_comp_t;


typedef struct {

    /* dtls fingerprint params */
    pc_dtls_key_type_t dtls_key_type;
    char fp_key[MAX_DTLS_FINGERPRINT_KEY_LEN+1];
    pc_dtls_role_t role;

    /* ice params */
    char ice_ufrag[PC_ICE_MAX_UFRAG_LEN];
    char ice_pwd[PC_ICE_MAX_PWD_LEN];
    char ice_options[PC_ICE_OPTIONS_LEN];

    /* TODO: check if this is really needed? */
    pc_media_dir_t dir;

    /* ice components */
    uint8_t num_comps;
    pc_ice_media_host_comp_t host_cands[PC_ICE_MAX_HOST_CANDS];

} pc_local_media_desc_t;


typedef struct {

    /* dtls fingerprint params */
    pc_dtls_key_type_t dtls_key_type;
    char fp_key[MAX_DTLS_FINGERPRINT_KEY_LEN+1];
    pc_dtls_role_t role;

    /* ice params */
    char ice_ufrag[PC_ICE_MAX_UFRAG_LEN];
    char ice_pwd[PC_ICE_MAX_PWD_LEN];
    char ice_options[PC_ICE_OPTIONS_LEN];

    /* TODO: check if this is really needed? */
    pc_media_dir_t dir;

} pc_media_desc_t;


typedef struct {

    /* socket descriptor on which data has been received */
    handle transport_param;

    /* source address of the received packet */
    mb_inet_addr_t  src;

    /* data buffer */
    uint8_t *buf;

    /* buffer length */
    uint32_t buf_len;

} pc_rcvd_data_t;


/* Note: make sure the contents are the same as one defined in trickle ice */
typedef struct
{
    bool eoc;
    ice_cand_params_t cand;
} pc_ice_cand_t;


typedef void (*pc_ice_candidates_cb) (
                handle pc, handle app_handle, ice_cand_params_t *c);
typedef void (*pc_ic_media_data_cb) (
                handle pc, handle app_handle, uint8_t *buf, uint32_t len);


mb_status_t pc_init(pc_ice_candidates_cb ice_cb, pc_ic_media_data_cb ic_media_cb);

mb_status_t pc_create_session(handle app_handle, handle *peerconn);

mb_status_t pc_destroy_session(handle peerconn);

mb_status_t pc_set_remote_media_description(
                    handle peerconn, pc_media_desc_t *desc);

mb_status_t pc_set_local_media_description(
                    handle peerconn, pc_local_media_desc_t *desc);

mb_status_t pc_set_remote_ice_candidate(handle peerconn, pc_ice_cand_t *cand);

mb_status_t pc_inject_received_data(handle peerconn, pc_rcvd_data_t *data);

mb_status_t pc_send_media_data(handle peerconn, uint8_t *media, uint32_t len);

mb_status_t pc_deinit(void);

mb_status_t pc_inject_timer_event(pc_timer_event_t *event);

mb_status_t pc_request_intra_video_frame(
        handle peerconn, uint32_t our_ssrc, uint32_t peer_ssrc);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

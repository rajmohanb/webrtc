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
#include <openssl/ssl.h>

/* srtp */
#include <srtp/srtp.h>

/* ice */
#include <stun_base.h>
#include <ice_api.h>

#include <mb_types.h>

#include <dtls_srtp.h>

#include <sctp.h>

#include <rtcp.h>

#include <pc.h>
#include <pc_int.h>

/* global pc instance */
pc_instance_t g_pc;
static pc_ice_candidates_cb pc_ice_cb; /* TODO;move this into global instance */
pc_ic_media_data_cb pc_media_cb; /* TODO; move this into global instance */


static char *ice_states[] =
{
    "ICE_GATHERED",
    "ICE_CC_RUNNING",
    "ICE_CC_COMPLETED",
    "ICE_CC_FAILED",
};



static int32_t pc_nwk_send_msg (u_char *buf, uint32_t buf_len, 
                    stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
                    uint32_t port, handle param)
{
    int sent_bytes = 0;
    int sock_fd = (int) param;

    if (ip_addr_type == STUN_INET_ADDR_IPV4)
    {
        sent_bytes = platform_socket_sendto(sock_fd, buf, 
                            buf_len, 0, AF_INET, port, (char *)ip_addr);

        MB_LOG(LOG_SEV_DEBUG, "Sent %d bytes on socket fd %d to %s:%d\n", 
                sent_bytes, sock_fd, ip_addr, port);
    }
    else if (ip_addr_type == STUN_INET_ADDR_IPV6)
    {
        sent_bytes = platform_socket_sendto(sock_fd, buf, 
                            buf_len, 0, AF_INET6, port, (char *)ip_addr);
    }
    else
    {
        MB_LOG (LOG_SEV_CRITICAL,
                "[ICE AGENT DEMO] Invalid IP address family type. "\
                "Sending of STUN message failed");
    }

    return sent_bytes;
}


static void pc_timer_expiry_cb (void *timer_id, void *arg)
{
    static int32_t timer_fd = 0;
    pc_timer_event_t timer_event;
    struct sockaddr_in dest;
    uint32_t bytes;

    platform_memset((char *) &dest, 0, sizeof(dest));

    MB_LOG (MBLOG_DEBUG,
            "[PC] in peerconn timer callback %d %p", timer_id, arg);

    if (timer_fd == 0)
    {
        timer_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(timer_fd == -1)
        {
            MB_LOG(MBLOG_CRITICAL, "[PC] Timer event socket creation failed");
            return;
        }
    }

    timer_event.timer_id = timer_id;
    timer_event.arg = arg;
    timer_event.timer_type = (uint8_t) PC_ICE_TIMER;


    dest.sin_family = AF_INET;
    dest.sin_port = htons(PC_TIMER_PORT);
    bytes = inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);
    if (bytes != 1) {
        perror("inet_pton:");
        MB_LOG (MBLOG_CRITICAL, 
                "%s: inet_pton() failed %d\n", dest, bytes);
        return;
    }

    bytes = sendto(timer_fd, (void *)&timer_event, 
            sizeof(timer_event), 0, (struct sockaddr *)&dest, sizeof(dest));
    if (bytes == -1)
    {
        perror("sendto:");
        MB_LOG(MBLOG_ERROR, "[PC] Sending of timer expiry message failed\n");
    }
    
    return;
}


static void pc_dtls_timer_expiry_cb (void *timer_id, void *arg)
{
    static int32_t timer_fd = 0;
    pc_timer_event_t timer_event;
    struct sockaddr_in dest;
    uint32_t bytes;

    platform_memset((char *) &dest, 0, sizeof(dest));

    fprintf(stderr, "DTLS SRTP Timer expired for arg [%p]\n", arg);

    MB_LOG (MBLOG_DEBUG,
            "[PC] in peerconn timer callback %d %p", timer_id, arg);

    if (timer_fd == 0)
    {
        timer_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(timer_fd == -1)
        {
            MB_LOG(MBLOG_CRITICAL, "[PC] Timer event socket creation failed");
            return;
        }
    }

    timer_event.timer_id = timer_id;
    timer_event.arg = arg;
    timer_event.timer_type = (uint8_t) PC_DTLS_TIMER;


    dest.sin_family = AF_INET;
    dest.sin_port = htons(PC_TIMER_PORT);
    bytes = inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);
    if (bytes != 1) {
        perror("inet_pton:");
        MB_LOG (MBLOG_CRITICAL, 
                "%s: inet_pton() failed %d\n", dest, bytes);
        return;
    }

    bytes = sendto(timer_fd, (void *)&timer_event, 
            sizeof(timer_event), 0, (struct sockaddr *)&dest, sizeof(dest));
    if (bytes == -1)
    {
        perror("sendto:");
        MB_LOG(MBLOG_ERROR, "[PC] Sending of timer expiry message failed\n");
    }
    
    return;
}


static handle pc_start_timer (uint32_t duration, handle arg)
{
    timer_expiry_callback timer_cb = pc_timer_expiry_cb;

    return platform_start_timer(duration, timer_cb, arg);
}


static int32_t pc_stop_timer (handle timer_id)
{
    if (platform_stop_timer(timer_id) == true)
        return STUN_OK;
    else
        return STUN_NOT_FOUND;
}


static handle pc_dtls_start_timer (uint32_t duration, handle arg)
{
    timer_expiry_callback timer_cb = pc_dtls_timer_expiry_cb;

    fprintf(stderr, "DTLS SRTP Timer started for arg [%p]\n", arg);

    return platform_start_timer(duration, timer_cb, arg);
}


static void pc_rx_data(handle h_inst, handle h_session, 
            handle h_media, uint32_t comp_id, void *data, uint32_t data_len)
{
    printf("Data returned for COMP ID: [%d] %s\n", comp_id, (char *)data);
    return;
}


static void pc_media_ice_candidate_handler(handle h_inst, handle h_session, 
                    handle h_media, handle app_handle, ice_cand_params_t *cand)
{
    pc_ctxt_t *ctxt = (pc_ctxt_t *)app_handle;
    pc_ice_cb(app_handle, ctxt->app_blob, cand);

    return;
}


static void pc_media_state_change_handler(handle h_inst, 
        handle h_session, handle h_media, ice_state_t state, handle app_handle)
{
    /* we are not interested in individual media states as of now */
    printf("************************************************************\n");
    printf("[PC] ICE media %p state changed to %s\n", 
                                        h_media, ice_states[state]);
    printf("************************************************************\n");

    return;
}



static void pc_session_state_change_handler(handle h_inst, 
                handle h_session, ice_state_t state, handle app_handle)
{
    mb_status_t status;
    pc_ctxt_t *ctxt = (pc_ctxt_t *) app_handle;

    if ((state >= ICE_GATHERED) && (state <= ICE_CC_FAILED))
    {
        printf("***********************************************************\n");
        printf("[PC] ICE session %p state changed to %s\n", 
                                            h_session, ice_states[state]);
        printf("***********************************************************\n");
    }

    switch(state)
    {
        case ICE_GATHERED: break;
        case ICE_CC_RUNNING: break;

        case ICE_CC_COMPLETED:
            printf("ICE negotiation completed, alert the local user\n");
            status = pc_fsm_inject_msg(ctxt, PC_E_ICE_COMPLETED, NULL, NULL);
            if (status != MB_OK) {
                fprintf(stderr, 
                        "Processing of event PC_E_ICE_COMPLETED failed\n");
            }
            break;

        case ICE_CC_FAILED:
            printf("ICE session failed, destroying session\n");
            status = pc_fsm_inject_msg(ctxt, PC_E_ICE_FAILED, NULL, NULL);
            if (status != MB_OK) {
                fprintf(stderr, "Processing of event PC_E_ICE_FAILED failed\n");
            }
            break;

        default: break;
    }

    return;
}



int pc_send_dtls_srtp_data (
            handle dtls, char *buf, int len, handle app_handle) {

    //char dest_ipaddr[48] = {0};
    pc_ctxt_t *ctxt = (pc_ctxt_t *) app_handle;
    int bytes = sendto(ctxt->sock_fd, buf, len, 0, 
            (struct sockaddr *)&ctxt->peer_addr, sizeof(struct sockaddr));
    if (bytes == -1) {
        perror("sendto ");
        fprintf(stderr, 
                "Error when sending DTLS data of size %d on socket\n", len);
        return bytes;
    }

    if (bytes < len) {
        fprintf(stderr, "ERROR: Data sent on "\
                "socket [%d] less than given size [%d]\n", bytes, len);
    }

    //fprintf(stderr, "[PC] Sent %d bytes of DTLS_SRTP data\n", bytes);
#if 0
    inet_ntop(AF_INET, &(ctxt->peer_addr.sin_addr), dest_ipaddr, ICE_IP_ADDR_MAX_LEN);

    fprintf(stderr, "[PC] Sent %d bytes of DTLS_SRTP data %s:%d\n", 
                                        bytes, dest_ipaddr, ctxt->peer_port);
#endif

    return bytes;
}



static void pc_dtls_incoming_app_data(
                handle dtls, char *buf, int len, handle app_handle) {

    mb_status_t status;
    pc_ctxt_t *ctxt = (pc_ctxt_t *)app_handle;

    status = dc_sctp_association_inject_received_msg(ctxt->dc, buf, len);
    if (status != MB_OK) {
        fprintf(stderr, "SCTP data channel processing "\
                "of received application message returned error\n");
    }

    return;
}



int pc_send_sctp_data (handle sctp, char *buf, int len, handle app_handle) {

    mb_status_t status;
    pc_ctxt_t *ctxt = (pc_ctxt_t *) app_handle;

    if (ctxt->state != PC_ACTIVE) return 0;

    status = dtls_srtp_session_send_app_data(ctxt->dtls, (uint8_t *)buf, len);
    if (status != MB_OK) {
        fprintf(stderr, "Failed to send SCTP data\n");
        return -1;
    }

    return len;
}



int pc_handle_peer_sctp_data(handle sctp, mb_media_type_t type, 
                void *data, uint32_t data_len, char *label, handle app_handle) {

    pc_ctxt_t *ctxt = (pc_ctxt_t *) app_handle;

    //fprintf(stderr, "PC: Received "
        //"SCTP data from peer len %d:%s\n", data_len, (char *)data);

    /* pass it to the higher application */
    pc_media_cb(ctxt, ctxt->app_blob, type, data, data_len, label);

    return 1;
}



mb_status_t pc_init(
        pc_ice_candidates_cb ice_cb, pc_ic_media_data_cb ic_media_cb) {

    mb_status_t status;
    int32_t ice_status;
    ice_instance_callbacks_t pc_cbs;
    ice_state_event_handlers_t pc_event_hdlrs;

    /* init platform */
    platform_init();

    /* init ice stack */
    ice_status = ice_create_instance(&g_pc.ice_instance);
    if (ice_status != STUN_OK) {
        printf("error: ice init failed with error code %d\n", ice_status);
        return MB_INT_ERROR;
    }

    pc_cbs.nwk_cb = pc_nwk_send_msg;
    pc_cbs.start_timer_cb = pc_start_timer;
    pc_cbs.stop_timer_cb = pc_stop_timer;
    pc_cbs.app_data_cb = pc_rx_data;

    ice_status = ice_instance_set_callbacks(g_pc.ice_instance, &pc_cbs);
    if (ice_status != STUN_OK)
    {
        MB_LOG (LOG_SEV_ERROR,
                "ice_instance_set_callbacks() returned error %d\n", ice_status);
        goto PC_ERROR_EXIT1;
    }

    pc_event_hdlrs.session_state_cb = pc_session_state_change_handler;
    pc_event_hdlrs.media_state_cb = pc_media_state_change_handler;
    pc_event_hdlrs.trickle_cand_cb = pc_media_ice_candidate_handler;

    ice_status = ice_instance_register_event_handlers(
                                g_pc.ice_instance, &pc_event_hdlrs);
    if (ice_status != STUN_OK)
    {
        MB_LOG (LOG_SEV_ERROR,
                "ice_instance_register_event_handlers() returned error %d\n",
                ice_status);
        goto PC_ERROR_EXIT1;
    }

    ice_status = ice_instance_set_client_software_name(
            g_pc.ice_instance, (u_char *)ICE_VENDOR_NAME, ICE_VENDOR_NAME_LEN);
    if (ice_status != STUN_OK)
    {
        MB_LOG (LOG_SEV_ERROR,
                "Setting of ICE agent vendor name failed,"\
                " returned error %d\n", ice_status);
        goto PC_ERROR_EXIT1;
    }

    ice_status = ice_instance_set_connectivity_check_nomination_mode(
                        g_pc.ice_instance, ICE_NOMINATION_TYPE_AGGRESSIVE);
    if (ice_status != STUN_OK) goto PC_ERROR_EXIT1;


    /* initialize the dtls_srtp library */
    status = dtls_srtp_init(pc_send_dtls_srtp_data, 
            pc_dtls_incoming_app_data, pc_dtls_start_timer, pc_stop_timer);
    if (status != MB_OK) {
        fprintf(stderr, "DTLS_SRTP module initialization failed\n");
        return status;
    }

    /* initialize the rtp stack */

    /* initialize the data channel (sctp) library */
    status = dc_sctp_init(pc_send_sctp_data, pc_handle_peer_sctp_data);
    if (status != MB_OK) {
        fprintf(stderr, "Data Channel SCTP module initialization failed\n");
        return status;
    }

    pc_ice_cb = ice_cb;
    pc_media_cb = ic_media_cb;

    return MB_OK;

PC_ERROR_EXIT1:
    ice_destroy_instance(g_pc.ice_instance);
    return MB_INT_ERROR;
}


mb_status_t pc_deinit(void) {

    int32_t ice_status;
    mb_status_t status;

    /* deinit the data channel (sctp) library */
    status = dc_sctp_deinit();
    if (status != MB_OK) {
        fprintf(stderr, "Data Channel SCTP module de-initialization failed\n");
    }


    /* deinit the rtp library */


    /* TODO: deinit the dtls_srtp library */

    ice_status = ice_destroy_instance(g_pc.ice_instance);
    if (ice_status != STUN_OK) {
        MB_LOG(MBLOG_ERROR, 
                "Destroying of ice instance failed: %d\n", ice_status);
        return MB_INT_ERROR;
    }

    /* TODO: deinit the platform */

    return MB_OK;
}


mb_status_t pc_create_session(handle app_handle, handle *peerconn) {

    mb_status_t status;
    int32_t ice_status;
    ice_stun_server_cfg_t stun_cfg;
    ice_relay_server_cfg_t turn_cfg;
    pc_ctxt_t *ctxt = (pc_ctxt_t *) calloc(1, sizeof(pc_ctxt_t));
    if (ctxt == NULL) {
        return MB_MEM_ERROR;
    }

    ctxt->state = PC_BORN;

    /* create ice session */
    ice_status = ice_create_session(g_pc.ice_instance, ICE_SESSION_INCOMING, 
                            ICE_MODE_FULL, (handle)ctxt, &ctxt->ice_session);
    if (ice_status != STUN_OK) {
        MB_LOG(MBLOG_ERROR, 
                "Creating of ice session failed: %d\n", ice_status);
        status = MB_INT_ERROR;
        goto MB_ERROR_1;
    }

    stun_cfg.server.host_type = STUN_INET_ADDR_IPV4;
    strncpy((char *)&stun_cfg.server.ip_addr, 
            STUN_SERVER_IP, ICE_IP_ADDR_MAX_LEN - 1);
    stun_cfg.server.port = STUN_SERVER_PORT;

    ice_status = ice_session_set_stun_server_cfg(
            g_pc.ice_instance, ctxt->ice_session, &stun_cfg);
    if (ice_status != STUN_OK) {
        MB_LOG(MBLOG_ERROR, "Configuring of STUN server "\
                "configuration to ice session failed: %d\n", ice_status);
        status = MB_INT_ERROR;
        goto MB_ERROR_2;
    }

    turn_cfg.server.host_type = STUN_INET_ADDR_IPV4;
    strncpy((char *)&turn_cfg.server.ip_addr, 
            TURN_SERVER_IP, ICE_IP_ADDR_MAX_LEN - 1);
    turn_cfg.server.port = TURN_SERVER_PORT;

    strncpy((char *)&turn_cfg.username, "asdfghjk", TURN_MAX_USERNAME_LEN - 1);
    strncpy((char *)&turn_cfg.credential, "zxcvbnm", TURN_MAX_PASSWORD_LEN - 1);
    strncpy((char *)&turn_cfg.realm, "mindbricks.com", TURN_MAX_REALM_LEN - 1);

    ice_status = ice_session_set_relay_server_cfg(
            g_pc.ice_instance, ctxt->ice_session, &turn_cfg);
    if (ice_status != STUN_OK) {
        MB_LOG(MBLOG_ERROR, "Configuring of TURN server "\
                "configuration to ice session failed: %d\n", ice_status);
        status = MB_INT_ERROR;
        goto MB_ERROR_2;
    }

    ctxt->app_blob = app_handle;

    *peerconn = ctxt;
    return MB_OK;

MB_ERROR_2:
    ice_destroy_session(g_pc.ice_instance, ctxt->ice_session);
MB_ERROR_1:
    free(ctxt);
    return status;
}


mb_status_t pc_destroy_session(handle peerconn) {

    mb_status_t status;
    err_status_t err;
    pc_ctxt_t *ctxt = (pc_ctxt_t *) peerconn;

    /* close sctp session */
    if (ctxt->dc) {
        status = dc_sctp_destroy_association(ctxt->dc);
        if (status != MB_OK) {
            fprintf(stderr, "Destroying of SCTP data "\
                    "channel association failed. Error: %d\n", status);
        }
    }

    if ((ctxt->state == PC_ACTIVE) || (ctxt->state == PC_DEAD)) {

        /* close srtp session */
        err = srtp_dealloc(ctxt->srtp_in);
        if (err != err_status_ok) {
            fprintf(stderr, 
                    "Deallocation of inbound srtp session failed: %d\n", err);
        }

        err = srtp_dealloc(ctxt->srtp_ob);
        if (err != err_status_ok) {
            fprintf(stderr, 
                    "Deallocation of outbound srtp session failed: %d\n", err);
        }
    }

    /* TODO: close dtls session */
    if (ctxt->dtls) {
        status = dtls_srtp_destroy_session(ctxt->dtls);
        if (status != MB_OK) {
            fprintf(stderr, 
                    "Destroying of DTLS session failed. Error: %d\n", status);
        }
    }

    ctxt->state = PC_DEAD;

    if (ctxt->ice_session)
        ice_destroy_session(g_pc.ice_instance, ctxt->ice_session);

    free(ctxt);

    return MB_OK;
}


mb_status_t pc_set_remote_media_description(
                    handle peerconn, pc_media_desc_t *desc) {

    pc_ctxt_t *ctxt = (pc_ctxt_t *)peerconn;

    return pc_fsm_inject_msg(ctxt, PC_E_PEER_MEDIA_PARAMS, desc, NULL);
}


mb_status_t pc_set_remote_ice_candidate(handle peerconn, pc_ice_cand_t *cand) {

    return pc_fsm_inject_msg(
            (pc_ctxt_t *)peerconn, PC_E_TRICKLED_ICE_CAND, cand, NULL);
}


mb_status_t pc_set_local_media_description(
                    handle peerconn, pc_local_media_desc_t *desc) {

    pc_ctxt_t *ctxt = (pc_ctxt_t *)peerconn;

    return pc_fsm_inject_msg(ctxt, PC_E_LOCAL_MEDIA_PARAMS, desc, NULL);
}

mb_status_t pc_inject_received_data(handle peerconn, pc_rcvd_data_t *data) {

    pc_ctxt_t *ctxt = (pc_ctxt_t *)peerconn;

    return pc_fsm_inject_msg(ctxt, PC_E_DATA, data, NULL);
}

mb_status_t pc_send_media_data(handle peerconn, 
        mb_media_type_t type, uint8_t *media, uint32_t len, char *label) {

    mb_status_t status;
    pc_ctxt_t *ctxt = (pc_ctxt_t *)peerconn;

    if (ctxt->state != PC_ACTIVE) {
        fprintf(stderr, 
                "Peer Connection not in active state. Current State: [%d]. "\
                "Discarding media to be sent to peer\n", ctxt->state);
        return MB_INVALID_PARAMS;
    }

    if ((type == MB_MEDIA_RTP) || (type == MB_MEDIA_RTCP)) {

        status = pc_utils_send_media_to_peer(ctxt, media, len);
        if (status != MB_OK) {
            fprintf(stderr, "Error %d while sending media data\n", status);
        }
    } else {

        status = dc_sctp_send_media_data(ctxt->dc, type, media, len, label);
        if (status != MB_OK) {
            fprintf(stderr, "Error %d while sending sctp data\n", status);
        }
    }

    return status;
}

mb_status_t pc_inject_timer_event(pc_timer_event_t *event) {

    int32_t status;
    handle ice_session;
    mb_status_t mb_status = MB_OK;


    if (event->timer_type == PC_ICE_TIMER) {

#if 0
        fprintf(stderr, "PC Timer fired. TimerID: %p and Arg:%p\n", 
                                            event->timer_id, event->arg);
#endif

        /* this does not need to go through the pc fsm */
        status = ice_session_inject_timer_event(
                            event->timer_id, event->arg, &ice_session);
        if (status != STUN_OK) {
            fprintf(stderr, "ICE stack timer event, returned %d\n", status);
            mb_status = MB_INT_ERROR;
        }
    } else if (event->timer_type == PC_DTLS_TIMER) {

        fprintf(stderr, "DTLS Timer fired. TimerID: %p and Arg:%p\n", 
                                            event->timer_id, event->arg);
        status = dtls_srtp_inject_timer_event(event->timer_id, event->arg);
        if (status != MB_OK) {
            fprintf(stderr, "Error! DTLS timer event, returned %d\n", status);
            mb_status = MB_INT_ERROR;
        }
    } else {

        fprintf(stderr, "Unknown timer type %d event fired\n", event->timer_type);
        mb_status = MB_INVALID_PARAMS;
    }

    /*
     * TODO: Really crude way of timer management. Currently we don't 
     * differentiate between ice timers and dtls timers. So as of now handling
     * in this way. If ICE reports that it is an invalid timer, then we pass it
     * on to dtls!!!
     */


    return mb_status;
}


mb_status_t pc_request_intra_video_frame(
        handle peerconn, uint32_t our_ssrc, uint32_t peer_ssrc) {

    mb_status_t status;
    uint32_t buf_len = 1500;
#if 0
    uint32_t i;
#endif
    uint8_t buf[1500];
    pc_ctxt_t *ctxt = (pc_ctxt_t *)peerconn;

    if (ctxt->state != PC_ACTIVE) {
        fprintf(stderr, 
                "Peer Connection not in active state. Current State: [%d]. "\
                "Hence not sending FIR as requested to peer\n", ctxt->state);
        return MB_INVALID_PARAMS;
    }

    status = rtcp_create_fir(buf, &buf_len, our_ssrc, peer_ssrc);
    if (status != MB_OK) {
        fprintf(stderr, "Unable to create RTCP FIR feedback message\n");
        return status;
    }

#if 0
    for (i = 0; i < buf_len; i+=4) {
        printf("%02X %02X %02X %02X\n", buf[i], buf[i+1], buf[i+2], buf[i+3]);
    }
#endif

    status = pc_utils_send_media_to_peer(ctxt, buf, buf_len);
    if (status != MB_OK) {
        fprintf(stderr, "Error %d while sending RTCP FIR packet\n", status);
    } else {
        fprintf(stderr, "sent RTCP FIR packet of len %d\n", buf_len);
    }

    return status;
}



/******************************************************************************/

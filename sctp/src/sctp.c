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

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <usrsctp.h>

#include <mb_types.h>

#include <sctp.h>
#include <sctp_int.h>


static dc_sctp_send_data_cb sctp_out;


static void mb_sctp_debug_printf(const char *format, ...) {

	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}


static int mb_sctp_send_data(void *addr, 
        void *buffer, size_t length, uint8_t tos, uint8_t set_df) {

    fprintf(stderr, "Need to send SCTP data of len: %d\n", length);

    sctp_out(addr, buffer, length, ((sctp_dc_assoc_t *)addr)->app_handle);

    return 0;
}


mb_status_t dc_sctp_init(dc_sctp_send_data_cb data_cb) {

    usrsctp_init(0, mb_sctp_send_data, mb_sctp_debug_printf);

#ifdef SCTP_DEBUG
    usrsctp_sysctl_set_setup_debug_on(SCTP_DEBUG_ALL);
#endif

    /* explicit congestion notification (disabled, as in ekr_peer.c) */
    usrsctp_sysctl_set_sctp_ecn_enable(0);

    sctp_out = data_cb;

    return MB_OK;
}



static int mb_receive_cb(struct socket *sock, 
        union sctp_sockstore addr, void *data, size_t datalen, 
        struct sctp_rcvinfo rcv, int flags, void *ulp_info)  {

    fprintf(stderr, " ***+++!!!!! Incoming DCEP MESSAGE? ***====@@@@\n");

    return 1;
}



mb_status_t dc_sctp_create_association(uint16_t local_port, 
                    uint16_t peer_port, handle app_handle, handle *sctp) {

    uint16_t i;
    sctp_dc_assoc_t *ctxt;
    struct sockaddr_conn sconn;
    struct sctp_event event;
    uint16_t event_types[] = {
        SCTP_ASSOC_CHANGE,
        SCTP_PEER_ADDR_CHANGE,
        SCTP_REMOTE_ERROR,
        SCTP_SEND_FAILED,
        SCTP_SHUTDOWN_EVENT,
        SCTP_ADAPTATION_INDICATION,
        SCTP_PARTIAL_DELIVERY_EVENT,
        SCTP_AUTHENTICATION_EVENT,
        SCTP_STREAM_RESET_EVENT,
        SCTP_SENDER_DRY_EVENT,
        SCTP_NOTIFICATIONS_STOPPED_EVENT,
        SCTP_ASSOC_RESET_EVENT,
        SCTP_STREAM_CHANGE_EVENT,
        SCTP_SEND_FAILED_EVENT,
    };

    fprintf(stderr, "Data Channel Association. "\
            "Local port [%d] and Peer port [%d]\n", local_port, peer_port);

    /* create a new data channel association context */
    ctxt = (sctp_dc_assoc_t *) calloc(1, sizeof(sctp_dc_assoc_t));
    if (ctxt == NULL) return MB_MEM_ERROR;

    usrsctp_register_address((void *)ctxt);
    ctxt->app_handle = app_handle;

    ctxt->s = usrsctp_socket(AF_CONN, 
            SOCK_STREAM, IPPROTO_SCTP, mb_receive_cb, NULL, 0, (void *)ctxt);
    if (ctxt->s == NULL) {
        perror("usrsctp_socket ");
        fprintf(stderr, "Error while creating usrsctp_socket\n");
        return MB_INT_ERROR;
    }

    /* make the socket non-blocking */
    if (usrsctp_set_non_blocking(ctxt->s, 1) < 0) {
        perror("usrsctp_set_non_blocking ");
    }

    /* TODO: look at enabling required setsockopt() properties */

    /* enable the events of interest */
    memset(&event, 0, sizeof(event));
    event.se_assoc_id = SCTP_ALL_ASSOC;
    event.se_on = 1;
    for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) {
        event.se_type = event_types[i];
        if (usrsctp_setsockopt(ctxt->s, 
                    IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
            perror("usrsctp_setsockopt ");
            fprintf(stderr, "usrsctp_setsockopt "\
                    "failed for event type %d\n", event_types[i]);
        }
    }

    /* bind */
    memset(&sconn, 0, sizeof(struct sockaddr_conn));
    sconn.sconn_family = AF_CONN;
    sconn.sconn_port = htons(local_port);
    sconn.sconn_addr = (void *)ctxt;
    if (usrsctp_bind(ctxt->s, 
                (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
        perror("usrsctp_bind ");
        fprintf(stderr, "Error while performing usrsctp_bind:\n");
        return MB_INT_ERROR;
    }

    /* connect - 
     * the call to usrsctp_connect() needs to be made ir-respective of whether
     * we are making use of connected UDP sockets or not. The call to 
     * usrsctp_connect() actually triggers the setting up of sctp association
     * and results in exchange of INIT, INIT_ACK, COOKIE_ECHO and COOKIE_ACK
     * sctp protocol messages.
     */
    memset(&sconn, 0, sizeof(struct sockaddr_conn));
    sconn.sconn_family = AF_CONN;
    sconn.sconn_port = htons(peer_port);
    sconn.sconn_addr = (void *)ctxt;
    if (usrsctp_connect(ctxt->s, 
                (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
        if (errno == EINPROGRESS) {
            /* operation is in progress, non-blocking call */
        } else {
            perror("usrsctp_connect ");
            fprintf(stderr, "Error while performing usrsctp_connect\n");
            return MB_INT_ERROR;
        }
    }

    /* we are done here? */

    *sctp = (handle) ctxt;

    return MB_OK;
}



mb_status_t dc_sctp_association_inject_received_msg(
                                        handle sctp, void *data, uint32_t len) {

    usrsctp_conninput(sctp, data, len, 0);

    return MB_OK;
}



mb_status_t dc_sctp_destroy_association(handle sctp) {

    return MB_OK;
}



mb_status_t dc_sctp_deinit(void) {

    if (usrsctp_finish() != 0) {
        fprintf(stderr, "usrsctp_finish returned error\n");
        return MB_INT_ERROR;
    }

    return MB_OK;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

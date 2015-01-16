/*******************************************************************************
*                                                                              *
*                Copyright (C) 2014-15, MindBricks Technologies                *
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

#ifdef MB_SCTP_DEBUG
#include <arpa/inet.h>
#endif

#include <usrsctp.h>

#include <mb_types.h>

#include <sctp.h>
#include <sctp_int.h>


static dc_sctp_send_data_cb sctp_out;
static dc_sctp_recv_data_cb sctp_in;
#ifdef MB_SCTP_DEBUG
int debug_sock;
#endif

static void mb_sctp_debug_printf(const char *format, ...) {

	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}


#ifdef MB_SCTP_DEBUG
void  mb_sctp_debug_packets(void *data, size_t datalen) {

    int bytes;
    struct sockaddr_in debug_dest;

    bzero(&debug_dest,sizeof(debug_dest));
    debug_dest.sin_family = AF_INET;
    debug_dest.sin_addr.s_addr=inet_addr("127.0.0.1");
    debug_dest.sin_port=htons(33333);

    bytes = sendto(debug_sock, data, datalen, 0, (struct sockaddr *)&debug_dest, sizeof(debug_dest));

    if (bytes == -1) {
        fprintf(stderr, "SCTP Debug: sending Received SCTP msg failed\n");
    }

    return;
}
#endif


static int mb_sctp_send_data(void *addr, 
        void *buffer, size_t length, uint8_t tos, uint8_t set_df) {

    fprintf(stderr, "Need to send SCTP data of len: %d\n", length);

    sctp_out(addr, buffer, length, ((sctp_dc_assoc_t *)addr)->app_handle);

    return 0;
}


mb_status_t dc_sctp_init(
        dc_sctp_send_data_cb data_cb, dc_sctp_recv_data_cb remote_data_cb) {

    usrsctp_init(0, mb_sctp_send_data, mb_sctp_debug_printf);

#ifdef SCTP_DEBUG
    usrsctp_sysctl_set_setup_debug_on(SCTP_DEBUG_ALL);
#endif

    /* explicit congestion notification (disabled, as in ekr_peer.c) */
    usrsctp_sysctl_set_sctp_ecn_enable(0);

    sctp_out = data_cb;
    sctp_in = remote_data_cb;

#ifdef MB_SCTP_DEBUG
    debug_sock = socket(AF_INET, SOCK_DGRAM, 0);
#endif

    return MB_OK;
}



static void handle_association_change_event(struct sctp_assoc_change *sac) {

	unsigned int i, n;

	printf("Association change ");
	switch (sac->sac_state) {
	case SCTP_COMM_UP:
		printf("SCTP_COMM_UP");
		break;
	case SCTP_COMM_LOST:
		printf("SCTP_COMM_LOST");
		break;
	case SCTP_RESTART:
		printf("SCTP_RESTART");
		break;
	case SCTP_SHUTDOWN_COMP:
		printf("SCTP_SHUTDOWN_COMP");
		break;
	case SCTP_CANT_STR_ASSOC:
		printf("SCTP_CANT_STR_ASSOC");
		break;
	default:
		printf("UNKNOWN");
		break;
	}
	printf(", streams (in/out) = (%u/%u)",
	       sac->sac_inbound_streams, sac->sac_outbound_streams);
	n = sac->sac_length - sizeof(struct sctp_assoc_change);
	if (((sac->sac_state == SCTP_COMM_UP) ||
	     (sac->sac_state == SCTP_RESTART)) && (n > 0)) {
		printf(", supports");
		for (i = 0; i < n; i++) {
			switch (sac->sac_info[i]) {
			case SCTP_ASSOC_SUPPORTS_PR:
				printf(" PR");
				break;
			case SCTP_ASSOC_SUPPORTS_AUTH:
				printf(" AUTH");
				break;
			case SCTP_ASSOC_SUPPORTS_ASCONF:
				printf(" ASCONF");
				break;
			case SCTP_ASSOC_SUPPORTS_MULTIBUF:
				printf(" MULTIBUF");
				break;
			case SCTP_ASSOC_SUPPORTS_RE_CONFIG:
				printf(" RE-CONFIG");
				break;
			default:
				printf(" UNKNOWN(0x%02x)", sac->sac_info[i]);
				break;
			}
		}
	} else if (((sac->sac_state == SCTP_COMM_LOST) ||
	            (sac->sac_state == SCTP_CANT_STR_ASSOC)) && (n > 0)) {
		printf(", ABORT =");
		for (i = 0; i < n; i++) {
			printf(" 0x%02x", sac->sac_info[i]);
		}
	}
	printf(".\n");
	if ((sac->sac_state == SCTP_CANT_STR_ASSOC) ||
	    (sac->sac_state == SCTP_SHUTDOWN_COMP) ||
	    (sac->sac_state == SCTP_COMM_LOST)) {
		exit(0);
	}
	return;
}



static void mb_sctp_handle_notification(
        sctp_dc_assoc_t *ctxt, union sctp_notification *notif, size_t n) {

	if (notif->sn_header.sn_length != (uint32_t)n) {
		return;
	}
	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		handle_association_change_event(&(notif->sn_assoc_change));
        printf("SCTP_ASSOC_CHANGE\n");
		break;
	case SCTP_PEER_ADDR_CHANGE:
		//handle_peer_address_change_event(&(notif->sn_paddr_change));
        printf("SCTP_PEER_ADDR_CHANGE\n");
		break;
	case SCTP_REMOTE_ERROR:
        printf("SCTP_REMOTE_ERROR\n");
		break;
	case SCTP_SHUTDOWN_EVENT:
        printf("SCTP_SHUTDOWN_EVENT\n");
		break;
	case SCTP_ADAPTATION_INDICATION:
        printf("SCTP_ADAPTATION_INDICATION\n");
		break;
	case SCTP_PARTIAL_DELIVERY_EVENT:
        printf("SCTP_PARTIAL_DELIVERY_EVENT\n");
		break;
	case SCTP_AUTHENTICATION_EVENT:
        printf("SCTP_AUTHENTICATION_EVENT\n");
		break;
	case SCTP_SENDER_DRY_EVENT:
        printf("SCTP_SENDER_DRY_EVENT\n");
		break;
	case SCTP_NOTIFICATIONS_STOPPED_EVENT:
        printf("SCTP_NOTIFICATIONS_STOPPED_EVENT\n");
		break;
	case SCTP_SEND_FAILED_EVENT:
		//handle_send_failed_event(&(notif->sn_send_failed_event));
        printf("SCTP_SEND_FAILED_EVENT\n");
		break;
	case SCTP_STREAM_RESET_EVENT:
        printf("SCTP_STREAM_RESET_EVENT\n");
		break;
	case SCTP_ASSOC_RESET_EVENT:
        printf("SCTP_ASSOC_RESET_EVENT\n");
		break;
	case SCTP_STREAM_CHANGE_EVENT:
        printf("SCTP_STREAM_CHANGE_EVENT\n");
		break;
	default:
		break;
	}
}



static int mb_sctp_handle_message(sctp_dc_assoc_t *ctxt, 
                    void *data, size_t datalen, struct sctp_rcvinfo *rcv) {

    char *label;
    uint32_t ppid;
    mb_media_type_t type;

#if 0
	uint16_t rcv_sid;
	uint16_t rcv_ssn;
	uint16_t rcv_flags;
	uint32_t rcv_ppid;
	uint32_t rcv_tsn;
	uint32_t rcv_cumtsn;
	uint32_t rcv_context;
	sctp_assoc_t rcv_assoc_id;
#endif

    ppid = ntohl(rcv->rcv_ppid);

    printf("Msg of length %d received on stream %d with SSN %u and TSN %u, PPID %d, context %u.\n",
           (int)datalen,
           rcv->rcv_sid,
           rcv->rcv_ssn,
           rcv->rcv_tsn,
           ntohl(rcv->rcv_ppid),
           rcv->rcv_context);

    switch(ppid) {

        case WEBRTC_DCEP:
            sctp_dcep_handle_message(ctxt, data, datalen, rcv);
            return 1;
            break;

        case WEBRTC_STRING:
            /* pass the data to application */
            //fprintf(stderr, "Received WEBRTC STRING data of len %d: %s\n", datalen, (char *)data);
            type = MB_SCTP_STRING;
            break;

        case WEBRTC_BINARY_PARTIAL:
            fprintf(stderr, "Received WEBRTC BINARY PARTIAL data of len %d\n", datalen);
            type = MB_SCTP_BINARY_PARTIAL;
            break;

        case WEBRTC_BINARY:
            fprintf(stderr, "Received WEBRTC BINARY data of len %d\n", datalen);
            type = MB_SCTP_BINARY;
            break;

        case WEBRTC_STRING_PARTIAL:
            fprintf(stderr, "Received WEBRTC STRING PARTIAL data of len %d: %s\n", datalen, (char *)data);
            type = MB_SCTP_STRING_PARTIAL;
            break;

        case WEBRTC_STRING_EMPTY:
            fprintf(stderr, "Received WEBRTC EMPTY STRING data of len %d\n", datalen);
            type = MB_SCTP_STRING_EMPTY;
            break;

        case WEBRTC_BINARY_EMPTY:
            fprintf(stderr, "Received WEBRTC EMPTY BINARY data of len %d\n", datalen);
            type = MB_SCTP_BINARY_EMPTY;
            break;

        default:
            fprintf(stderr, "Received data of len %d for unknown PPID %d\n", datalen, ppid);
            /* 
             * TODO - draft-ietf-rtcweb-data-channel-12 Section 6.6
             * if an unsupported ppid is rcvd, the data channel should be closed.
             */
            return 1;
            break;
    }

    label = ctxt->channels[rcv->rcv_sid].label;
    sctp_in(ctxt, type, data, datalen, label, ctxt->app_handle);

    return 1;
}



static int mb_sctp_receive_cb(struct socket *sock, 
        union sctp_sockstore addr, void *data, size_t datalen, 
        struct sctp_rcvinfo rcv, int flags, void *ulp_info)  {

    sctp_dc_assoc_t *ctxt = (sctp_dc_assoc_t *)ulp_info;

    fprintf(stderr, " ***+++!!!!! Incoming DCEP MESSAGE of Len %d? ***====@@@@\n", datalen);

	if (data) {
		if (flags & MSG_NOTIFICATION) {
			mb_sctp_handle_notification(ctxt, (union sctp_notification *)data, datalen);
		} else {
            mb_sctp_handle_message(ctxt, data, datalen, &rcv);
		}
		free(data);
	}

	return 1;
}



mb_status_t dc_sctp_create_association(uint16_t local_port, 
                                   uint16_t peer_port, uint16_t is_dtls_client, 
                                   handle app_handle, handle *sctp) {

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
            SOCK_STREAM, IPPROTO_SCTP, mb_sctp_receive_cb, NULL, 0, (void *)ctxt);
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

    ctxt->is_dtls_client = is_dtls_client;

    /* we are done here? */

    *sctp = (handle) ctxt;

    return MB_OK;
}



mb_status_t dc_sctp_association_inject_received_msg(
                                        handle sctp, void *data, uint32_t len) {

#ifdef MB_SCTP_DEBUG
    mb_sctp_debug_packets(data, len);
#endif

    usrsctp_conninput(sctp, data, len, 0);

    return MB_OK;
}



mb_status_t dc_sctp_send_media_data(handle sctp, 
            mb_media_type_t type, void *data, uint32_t data_len, char *label) {

    uint32_t i, ppid;
    sctp_dc_channel_t *channel;
    struct sctp_sendv_spa spainfo;
    sctp_dc_assoc_t *ctxt = (sctp_dc_assoc_t *)sctp;

    switch(type) {

        case MB_SCTP_STRING: ppid = WEBRTC_STRING; break;
        case MB_SCTP_STRING_PARTIAL: ppid = WEBRTC_STRING_PARTIAL; break;
        case MB_SCTP_STRING_EMPTY: ppid = WEBRTC_STRING_EMPTY; break;
        case MB_SCTP_BINARY: ppid = WEBRTC_BINARY; break;
        case MB_SCTP_BINARY_PARTIAL: ppid = WEBRTC_BINARY_PARTIAL; break;
        case MB_SCTP_BINARY_EMPTY: ppid = WEBRTC_BINARY_EMPTY; break;

        case MB_MEDIA_RTP:
        case MB_MEDIA_RTCP:
        default:
            fprintf(stderr, "Invalid/Unknown sctp media "\
                    "type %d received for sending to peer. Dropping!\n", type);
            break;
    }

    /* TODO - 
     * this way we will end up sending on the first channel always! Not fair. 
     * Either pass channel id along with the data or use the label? 
     */

    /* find a channel to send data */
    for (i = 0; i < SCTP_MAX_DATA_CHANNELS; i++)
        if ((ctxt->channels[i].label) && 
                (strncmp(label, ctxt->channels[i].label, strlen(label)) == 0))
            break;

    if (i == SCTP_MAX_DATA_CHANNELS) {
        fprintf(stderr, "Error! Not able to "\
                "find channel to send data for given label [%s]\n", label);
        return MB_TRANSPORT_FAIL;
    }

    channel = &ctxt->channels[i];

    if (ctxt->in_streams[i].state != DCEP_STREAM_OPEN) {
        fprintf(stderr, "Error! Found channel for given label [%s]. But "\
                "it's state is %d and not OPEN as expected. Hence dropping "\
                "sending of message\n", label, ctxt->in_streams[i].state);
        return MB_TRANSPORT_FAIL;
    }

    memset(&spainfo, 0, sizeof(spainfo));

    /* fill in the send info deatils as per rfc 6458 */
    spainfo.sendv_flags = SCTP_SEND_SNDINFO_VALID;

    spainfo.sendv_sndinfo.snd_sid = i;
    spainfo.sendv_sndinfo.snd_flags = SCTP_EOR;
	spainfo.sendv_sndinfo.snd_ppid = htonl(ppid);
	//spainfo.sendv_sndinfo.snd_context = 
	//spainfo.sendv_sndinfo.snd_assoc_id = 
    switch(channel->channel_type) {

        case DCEP_CHANNEL_RELIABLE_UNORDERED:
        case DCEP_CHANNEL_PR_REXMIT_UNORDERED:
        case DCEP_CHANNEL_PR_TIMED_UNORDERED:
            spainfo.sendv_sndinfo.snd_flags |= SCTP_UNORDERED;
            break;

        default:
            break;
    }

    if ((channel->channel_type == DCEP_CHANNEL_PR_REXMIT_UNORDERED) ||
            (channel->channel_type == DCEP_CHANNEL_PR_REXMIT)) {

        spainfo.sendv_flags |= SCTP_SEND_PRINFO_VALID;
        spainfo.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
        spainfo.sendv_prinfo.pr_value = channel->reliability_param;
    } else if ((channel->channel_type == DCEP_CHANNEL_PR_TIMED) ||
            (channel->channel_type == DCEP_CHANNEL_PR_TIMED_UNORDERED)) {
        spainfo.sendv_flags |= SCTP_SEND_PRINFO_VALID;
        spainfo.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
        spainfo.sendv_prinfo.pr_value = channel->reliability_param;
    }

    if (usrsctp_sendv(ctxt->s, data, data_len, 
                NULL, 0, &spainfo, sizeof(spainfo), SCTP_SENDV_SPA, 0) < 0) {

        fprintf(stderr, "usrsctp_sendv: Sending of sctp app data failed\n");
        return MB_TRANSPORT_FAIL;
    }

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

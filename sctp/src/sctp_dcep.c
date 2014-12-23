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

#ifdef MB_SCTP_DEBUG
#include <arpa/inet.h>
int debug_sock;
#endif



mb_status_t sctp_dcep_handle_data_channel_ack(sctp_dc_assoc_t *ctxt, 
                        void *data, size_t datalen, struct sctp_rcvinfo *rcv) {

#if 0
    sctp_dc_open_msg_t *open = (sctp_dc_open_msg_t *)data;

    fprintf(stderr, "DCEP OPEN Msg Type");
#endif
    return MB_OK;
}



mb_status_t sctp_dcep_send_ack(sctp_dc_assoc_t *ctxt, uint16_t stream_id) {

    sctp_dc_ack_msg_t ack;
    struct sctp_sndinfo sndinfo;

    memset(&ack, 0, sizeof(ack));
    ack.msg_type = DCEP_DATA_CHANNEL_ACK;

    /* send this across */
    memset(&sndinfo, 0, sizeof(sndinfo));

    sndinfo.snd_sid = stream_id;
    sndinfo.snd_flags = SCTP_EOR;
	sndinfo.snd_ppid = htonl(WEBRTC_DCEP);
	//sndinfo.snd_context = 
	//sndinfo.snd_assoc_id = 
    if (usrsctp_sendv(ctxt->s, &ack, sizeof(sctp_dc_ack_msg_t), NULL, 
                0, &sndinfo, sizeof(sndinfo), SCTP_SENDV_SNDINFO, 0) < 0) {

        fprintf(stderr, "usrsctp_sendv: Sending of DCEP ACK message failed\n");
        return MB_TRANSPORT_FAIL;
    }

   fprintf(stderr, "sent DCEP ACK\n");

    return MB_OK;
}



mb_status_t sctp_dcep_handle_data_channel_open(sctp_dc_assoc_t *ctxt, 
                        void *data, size_t datalen, struct sctp_rcvinfo *rcv) {

    uint16_t sval, stream_id;
    uint32_t lval;
    mb_status_t status;
    uint8_t *msg = (uint8_t *)data;
    sctp_dc_channel_t *channel;
    sctp_dc_open_msg_t *open = 
        (sctp_dc_open_msg_t *) calloc(1, sizeof(sctp_dc_open_msg_t));

    open->msg_type = *msg;
    open->channel_type = *(msg+1);
    msg += 2;
    memcpy(&sval, msg, sizeof(uint16_t));
    open->priority = ntohs(sval);
    msg += 2;
    memcpy(&lval, msg, sizeof(uint32_t));
    open->reliability_param = ntohl(lval);
    msg += 4;

    memcpy(&sval, msg, sizeof(uint16_t));
    open->label_len = ntohs(sval);
    msg += 2;
    memcpy(&sval, msg, sizeof(uint16_t));
    open->protocol_len = ntohs(sval);
    msg += 2;

    if (open->label_len) {

        open->label = (char *) calloc(1, open->label_len+1);
        if (!open->label) return MB_MEM_ERROR;

        memcpy(open->label, msg, open->label_len);
        msg += open->label_len;
    }

    if (open->protocol_len) {

        open->protocol = (char *) calloc(1, open->protocol_len+1);
        if (!open->protocol) return MB_MEM_ERROR;

        memcpy(open->protocol, msg, open->protocol_len);
        msg += open->protocol_len;
    }

    fprintf(stderr, "DCEP OPEN - Msg Type: %d\n", open->msg_type);
    fprintf(stderr, "DCEP OPEN - Channel Type: %d\n", open->channel_type);
    fprintf(stderr, "DCEP OPEN - Priority: %d\n", open->priority);
    fprintf(stderr, "DCEP OPEN - Reliability Param: %d\n", open->reliability_param);

    fprintf(stderr, "DCEP OPEN - Label Length: %d\n", open->label_len);
    fprintf(stderr, "DCEP OPEN - Protocol Length: %d\n", open->protocol_len);

    if (open->label_len) fprintf(stderr, "DCEP OPEN - Label: %s\n", open->label);
    if (open->protocol_len) fprintf(stderr, "DCEP OPEN - Protocol: %s\n", open->protocol);

#ifdef MB_SCTP_DEBUG
    mb_sctp_debug_packets(data, datalen);
#endif

    /* draft-ietf-rtcweb-data-protocol-08 - Section 6: Procedures */

    /* 
     * now check if the stream proposed by the peer is available and is valid 
     * or not. A DTLS client must make use of even stream identifier and the 
     * one acting as DTLS server must make use of odd stream identifiers.
     */

/*
    struct sctp_rcvinfo =>

    rcv_sid - stream id
    rcv_ssn - Stream Sequence Number, 
              16 bit unique id for user msg within each stream
    rcv_flags - ?
    rcv_ppid - SCTP Protocol Payload IDentifier
    rcv_tsn - Transmission Sequence Number, unique 32bit id for each data chunk
    rcv_cumtsn - Cumulative TSN, the TSN of the last data chunk acknowledged 
                 via the Cumulative TSN Ack field of a SACK 
    rcv_context - ?
    rcv_assoc_id - ?
*/
    stream_id = rcv->rcv_sid;
    if ((stream_id % 2 == 0) && (ctxt->is_dtls_client == 1)) {
        fprintf(stderr, "Even Stream Id received in DATA_CHANNEL_OPEN msg "
                "from remote when local agent is DTLS CLIENT. ERROR!!! TODO\n");
        /* TODO
         * draft-ietf-rtcweb-data-protocol-08 Sec 6: Procedures 
         * close the data channel 
         */
        return MB_OK;
    }

    if (stream_id >= SCTP_MAX_DATA_STREAMS) {
        fprintf(stderr, "Stream Id No %d received from peer is more than the "\
                "implementation defined array. ERROR!!! TODO\n", stream_id);
        /* TODO - close the channel */
        return MB_OK;
    }

    fprintf(stderr, "STREAM ID: %d\n", stream_id);

    /* check if the received stream id is available */
    if (ctxt->in_streams[stream_id].state != DCEP_STREAM_UNUSED) {
        fprintf(stderr, "The stream id %d received from peer is already "\
                "being used. TODO Need to close the data channel\n", stream_id);
        /* TODO - close the channel */
        return MB_OK;
    }

    /* the channel/stream is unused */
    channel = &ctxt->channels[stream_id];

    channel->channel_type = open->channel_type;
    //channel->is_in_order - Depends on channel type above
    //channel->is_reliable - Depends on channel type above
    channel->reliability_param = open->reliability_param;
    channel->priority = open->priority;
    if (open->label) channel->label = strdup(open->label);
    if (open->protocol) channel->protocol = strdup(open->protocol);

    /* send ack */
    status = sctp_dcep_send_ack(ctxt, stream_id);
    if (status != MB_OK) {
        fprintf(stderr, "Error sending DATA_CHANNEL_ACK message\n");
        return status;
    }

    return status;
}



mb_status_t sctp_dcep_handle_message(sctp_dc_assoc_t *ctxt, 
                void *data, size_t datalen, struct sctp_rcvinfo *rcv) {

    switch(*((char *)data)) {

        case DCEP_DATA_CHANNEL_ACK:
            sctp_dcep_handle_data_channel_ack(ctxt, data, datalen, rcv);
            break;

        case DCEP_DATA_CHANNEL_OPEN:
            sctp_dcep_handle_data_channel_open(ctxt, data, datalen, rcv);
            break;

        default:
            break;
    }

    return 1;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

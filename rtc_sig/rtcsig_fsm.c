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
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#include <libwebsockets.h>

#include <jansson.h>

#include <mb_types.h>

#include <rtcsig.h>


static char* rtc_states[] ={
    "RTC_OFFLINE",
    "RTC_SIGNING_IN",
    "RTC_ONLINE",
    "RTC_OFFERED",
    "RTC_GOT_ANSWER",
    "RTC_LIVE",
};


extern int media_server_fd;
extern struct libwebsocket_context *context;
extern struct libwebsocket_protocols protocols[];

static mb_status_t rtcsig_ignore_msg (
        rtcsig_session_t *session, handle h_msg, handle h_param);

static mb_status_t rtcsig_signin (
        rtcsig_session_t *session, handle h_msg, handle h_param);

static mb_status_t rtcsig_peers (
        rtcsig_session_t *session, handle h_msg, handle h_param);

static mb_status_t rtcsig_ic (
        rtcsig_session_t *session, handle h_msg, handle h_param);

static mb_status_t rtcsig_peer_ice (
        rtcsig_session_t *session, handle h_msg, handle h_param);

static mb_status_t rtcsig_new_peer (
        rtcsig_session_t *session, handle h_msg, handle h_param);

static mb_status_t rtcsig_local_media (
        rtcsig_session_t *session, handle h_msg, handle h_param);

static mb_status_t rtcsig_local_ice (
        rtcsig_session_t *session, handle h_msg, handle h_param);



static rtcsig_fsm_handler 
    rtcsig_session_fsm[RTC_STATE_MAX][RTC_EVENT_MAX] =
{
    /** RTC_OFFLINE */
    {
        rtcsig_signin,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
    },
    /** RTC_SIGNING_IN */
    {
        rtcsig_ignore_msg,
        rtcsig_peers,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
    },
    /** RTC_ONLINE */
    {
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ic,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_new_peer,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
    },
    /** RTC_GOT_OFFER */
    {
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_peer_ice,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_local_media,
        rtcsig_local_ice,
    },
    /** RTC_LIVE */
    {
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_peer_ice,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_ignore_msg,
        rtcsig_local_ice,
    }
};




static mb_status_t rtcsig_local_media (
        rtcsig_session_t *session, handle h_msg, handle h_param) {

    json_t *root, *sdp, *data, *desc;
    char *sdp_buf = (char *)h_msg;
    char *ans = NULL;
    int l = 0, n;

    sdp_buf[(int)h_param] = 0; /* Fix for non-utf8 characters */
    printf("Received answer to be sent of len %d: %s\n", (int)h_param, sdp_buf); 

    sdp = json_object();
    desc = json_string(sdp_buf);
    if (desc == NULL) { printf("Failure 0\n"); }
    n = json_object_set_new(sdp, "sdp", desc);
    if (n == -1) { printf("Failure 1\n"); } 
    n = json_object_set_new(sdp, "type", json_string("answer"));
    if (n == -1) { printf("Failure 2\n"); } 

    data = json_object();
    n = json_object_set_new(data, "socketId", json_string(session->peer));
    n = json_object_set_new(data, "sdp", sdp);

    root = json_object();
    json_object_set_new(root, "eventName", json_string("send_answer"));
    json_object_set_new(root, "data", data);

    ans = json_dumps(root, JSON_PRESERVE_ORDER);
    if (!ans) {
        fprintf(stderr, "JSON encoding of message failed\n");
        return MB_INT_ERROR;
    }

    fprintf(stderr, "Answer: %s\n", ans);
    l = strlen(ans);

    session->ringbuffer[session->ringbuffer_head].payload = 
        malloc(LWS_SEND_BUFFER_PRE_PADDING + l + LWS_SEND_BUFFER_POST_PADDING); 

    session->ringbuffer[session->ringbuffer_head].len = l;
    memcpy((char *)session->ringbuffer[session->ringbuffer_head].payload + 
            LWS_SEND_BUFFER_PRE_PADDING, ans, l);

    if (session->ringbuffer_head == (MAX_MESSAGE_QUEUE - 1))
        session->ringbuffer_head = 0;
    else
        session->ringbuffer_head++;

    libwebsocket_callback_on_writable_all_protocol(
                        libwebsockets_get_protocol(session->wsi));

    session->state = RTC_LIVE;

    free(ans);

    return MB_OK;
}



static mb_status_t rtcsig_local_ice (
        rtcsig_session_t *session, handle h_msg, handle h_param) {

    json_t *root, *data;
    char *tmp1, *tmp2, *rcvd_buf = (char *)h_msg;
    char *ice = NULL;
    int l = 0, n;
    char oneline[128];

    fprintf(stderr, "Received ICE information of len "\
            "[%d] from media server: %s\n", (int)h_param, rcvd_buf);

    tmp1 = rcvd_buf;
    while((tmp1 = strstr(tmp1, "a=candidate:")) != NULL) {

        memset(oneline, 0, sizeof(oneline));

        tmp2 = strstr((tmp1+1), "a=candidate:");

        if (tmp2) strncpy(oneline, tmp1, (tmp2-tmp1));

        data = json_object();
        json_object_set_new(data, "label", json_integer(0));
        if (tmp2)
            json_object_set_new(data, "candidate", json_string(oneline));
        else
            json_object_set_new(data, "candidate", json_string(tmp1));
        json_object_set_new(data, "socketId", json_string(session->peer));

        root = json_object();
        json_object_set_new(root, "eventName", json_string("send_ice_candidate"));
        json_object_set_new(root, "data", data);

        ice = json_dumps(root, JSON_PRESERVE_ORDER);
        if (!ice) {
            fprintf(stderr, "JSON encoding of message failed\n");
            return MB_INT_ERROR;
        }

        fprintf(stderr, "ICE Candidate: %s\n", ice);
        l = strlen(ice);

        session->ringbuffer[session->ringbuffer_head].payload = 
            malloc(LWS_SEND_BUFFER_PRE_PADDING + l + LWS_SEND_BUFFER_POST_PADDING); 

        session->ringbuffer[session->ringbuffer_head].len = l;
        memcpy((char *)session->ringbuffer[session->ringbuffer_head].payload + 
                LWS_SEND_BUFFER_PRE_PADDING, ice, l);

        if (session->ringbuffer_head == (MAX_MESSAGE_QUEUE - 1))
            session->ringbuffer_head = 0;
        else
            session->ringbuffer_head++;

        libwebsocket_callback_on_writable_all_protocol(
                            libwebsockets_get_protocol(session->wsi));

        if (tmp2 == NULL) break;
        tmp1 = tmp2;

        free(ice);
    }

    return MB_OK;
}



static mb_status_t rtcsig_new_peer (
        rtcsig_session_t *session, handle h_msg, handle h_param) {

    json_t *root, *data, *peer;

    root = (json_t *) h_msg;

    data = json_object_get(root, "data");
    if (!json_is_object(data)) {

        fprintf(stderr, "Error: extracting data from json string\n");
        return MB_INVALID_PARAMS;
    }

    peer = json_object_get(data, "socketId");
    if (!json_is_string(peer)) {

        fprintf(stderr, "Error: extracting sdp data from json string\n");
        return MB_INVALID_PARAMS;
    }

    session->peer = json_string_value(peer);

    return MB_OK;
}



static mb_status_t rtcsig_peer_ice (
        rtcsig_session_t *session, handle h_msg, handle h_param) {

    char *ice;
    int bytes, ice_label;
    json_t *root, *data, *cand, *label;

    root = (json_t *) h_msg;

    /*
     * Hack!
     * This will only work with Chrome (and Opera) probably for now
     * Since Chrome uses BUNDLE and rtcp-mux, we discard any ICE candidate with
     * a label anything other than "label" = "0".
     * We can add more content here later to make it intelligent and not
     * use the hack!
     */
    data = json_object_get(root, "data");
    if (!json_is_object(data)) {

        fprintf(stderr, "Error: extracting data from json string\n");
        return MB_INVALID_PARAMS;
    }

    label = json_object_get(data, "label");
    ice_label = json_typeof(label);
    printf("LABEL JSON TYPE: %d\n", ice_label);
    if (!json_is_integer(label)) {

        fprintf(stderr, "Error: extracting label value from json string\n");
        return MB_INVALID_PARAMS;
    }

    ice_label = json_integer_value(label);
    if (ice_label != 0) {

        fprintf(stderr, "Discarding ICE candidate with Label: %d\n", ice_label);
        return MB_INVALID_PARAMS;
    }

    cand = json_object_get(data, "candidate");
    if (!json_is_string(cand)) {

        fprintf(stderr, "Error: extracting sdp data from json string\n");
        return MB_INVALID_PARAMS;
    }

    ice = json_string_value(cand);

    fprintf(stderr, "Received Peer ICE: %s\n", ice);

    /* send it to bcast media server */
    /* TODO; put a loop to make sure all data sent */
    bytes = send(media_server_fd, ice, strlen(ice), 0);
    if (bytes == -1) {

        perror("send ");
        fprintf(stderr, "Unable to send data to media server\n");
        return MB_INT_ERROR;
    }

    /* remain in same state */

    return MB_OK;
}



static mb_status_t rtcsig_ic (
        rtcsig_session_t *session, handle h_msg, handle h_param) {

    char *sdp;
    int bytes;
    json_t *root, *data, *sdp1, *sdp2;

    root = (json_t *) h_msg;

    data = json_object_get(root, "data");
    if (!json_is_object(data)) {

        fprintf(stderr, "Error: extracting data from json string\n");
        return MB_INVALID_PARAMS;
    }

    sdp1 = json_object_get(data, "sdp");
    if (!json_is_object(sdp1)) {

        fprintf(stderr, "Error: extracting sdp data from json string\n");
        return MB_INVALID_PARAMS;
    }

    sdp2 = json_object_get(sdp1, "sdp");
    if (!json_is_string(sdp2)) {

        fprintf(stderr, "Error: extracting sdp data from json string\n");
        return MB_INVALID_PARAMS;
    }

    sdp = json_string_value(sdp2);

    fprintf(stderr, "Received Peer SDP: %s\n", sdp);

    /* send it to bcast media server */
    /* TODO; put a loop to make sure all data sent */
    bytes = send(media_server_fd, sdp, strlen(sdp), 0);
    if (bytes == -1) {

        perror("send ");
        fprintf(stderr, "Unable to send data to media server\n");
        return MB_INT_ERROR;
    }

    session->state = RTC_GOT_OFFER;

    return MB_OK;
}

static mb_status_t rtcsig_peers (
        rtcsig_session_t *session, handle h_msg, handle h_param) {

    char *you;
    int16_t i;
    json_t *root, *event, *data, *you_id, *conns;

    root = (json_t *) h_msg;

    event = json_object_get(root, "eventName");
    if (!json_is_string(event)) {

        fprintf(stderr, "error: eventName is not a string\n");
        return MB_INVALID_PARAMS;
    }

    you = json_string_value(event);

    if (strncasecmp(you, "get_peers", 9) != 0) {

        fprintf(stderr, "error: eventName string is not as expected\n");
        fprintf(stderr, "Received eventName: %s\n", you);
        return MB_INVALID_PARAMS;
    }

    data = json_object_get(root, "data");
    if (!json_is_object(data)) {

        fprintf(stderr, "error: data is not an object\n");
        return MB_INVALID_PARAMS;
    }

    you_id = json_object_get(data, "you");
    if (!json_is_object(data)) {

        fprintf(stderr, "error: Extracting 'you' id from json response\n");
        return MB_INVALID_PARAMS;
    }

    session->you = json_string_value(you_id);
    json_incref(you_id);

    conns = json_object_get(data, "connections");
    if (!json_is_array(conns)) {

        fprintf(stderr, "error: Extracting peers ids from json response\n");
        return MB_INVALID_PARAMS;
    }

    for(i = 0; i < json_array_size(conns); i++) {

        json_t *peer;

        peer = json_array_get(conns, i);
        if (!json_is_string(peer)) {

            fprintf(stderr, "error: Extracting peers ids from json object\n");
            return MB_INVALID_PARAMS;
        }

        session->peer = json_string_value(peer);
        json_incref(peer);

        /* TODO; we handle only one peer connection id as of now */
        break;
    }

    session->state = RTC_ONLINE;

    return MB_OK;
}

static mb_status_t rtcsig_signin (
        rtcsig_session_t *session, handle h_msg, handle h_param) {

    int l = 0, n;
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 1024 +
						  LWS_SEND_BUFFER_POST_PADDING];

    /* sign in, join the room */

    l += sprintf((char *)&buf[LWS_SEND_BUFFER_PRE_PADDING + l], 
            "{\"eventName\":\"join_room\", \"data\":{\"room\":\"\"}}");
    n = libwebsocket_write(session->wsi, 
            &buf[LWS_SEND_BUFFER_PRE_PADDING], l, LWS_WRITE_TEXT);

    if (n < 0) {
        lwsl_err("NO write LWS_CALLBACK_CLIENT_WRITEABLE\n");
        return -1;
    }

    if (n < l) {
        lwsl_err("Partial write LWS_CALLBACK_CLIENT_WRITEABLE\n");
        return -1;
    }
    fprintf(stderr, "Sent %d bytes to signaling server\n", n);

    session->state = RTC_SIGNING_IN;

    return MB_OK;
}


static mb_status_t rtcsig_ignore_msg (
        rtcsig_session_t *session, handle h_msg, handle h_param) {

    MB_LOG(MBLOG_ERROR, "Event ignored");
    return MB_OK;
}


mb_status_t rtcsig_session_fsm_inject_msg(rtcsig_session_t *session, 
                rtcsig_event_t event, handle h_msg, handle h_param) {

    int32_t status;
    rtcsig_fsm_handler handler;
    rtcsig_state_t cur_state;

    cur_state = session->state;
    handler = rtcsig_session_fsm[cur_state][event];

    if (!handler) return MB_INVALID_PARAMS;

    status = handler(session, h_msg, h_param);

    if (cur_state != session->state)
    {
        fprintf(stderr, "Session stage changed to %s\n", 
                                    rtc_states[session->state]);
    }

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

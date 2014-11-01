
#include <stdio.h>
#include <stdint.h>

#include <sdp.h>

#include <jansson.h>

#include <mb_types.h>
#include <stun_base.h>

#include <ice_api.h>
#include <pc.h>

#include <livecast.h>


extern rtc_bcast_session_t g_session;

mb_status_t rtcmedia_process_new_channel_req(json_t *msg) {

    /*
     1. create new channel(session)
     2. add the id of the broadcaster
     3. send offer
     */
    char *id;
    json_t *data, *b_id;
    rtc_bcast_session_t *s = &g_session;
    rtc_participant_t *p = &(s->tx);
    pc_local_media_desc_t local_desc;
    mb_status_t status;
    int fd;
    handle pc_handle;

    memset(&local_desc, 0, sizeof(local_desc));

    data = json_object_get(msg, "data");
    if (!json_is_object(data)) {

        fprintf(stderr, "Error: extracting data from json object\n");
        return MB_INVALID_PARAMS;
    }

    b_id = json_object_get(data, "socketId");
    if (!json_is_string(b_id)) {

        fprintf(stderr, "Error: extracting socket id from json string\n");
        return MB_INVALID_PARAMS;
    }

    id = json_string_value(b_id);
    if (!id) {

        fprintf(stderr, "Error: Getting string parameter value\n");
        return MB_INVALID_PARAMS;
    }

    p->id = strdup(id);

    /* this participant is the broadcaster? */
    p->is_broadcaster = true;
    p->session = s;

    /* generate new ssrcs */
    s->my_vid_ssrc1 = 323445672;
    s->my_vid_ssrc2 = 986765443;
    s->my_aud_ssrc = 658750432;
    s->my_app_ssrc = 132407700;

    fprintf(stderr, "New channel created with broadcaster id: %s\n", p->id);

    return status;
}



mb_status_t rtcmedia_process_offer(json_t *msg) {

    char *id, *sdp_buf;
    rtc_bcast_session_t *s = &g_session;
    rtc_participant_t *p;
    json_t *sdp_outer, *sdp_inner, *peer_id, *data;
    sdp_session_t *sdp;
    sdp_parser_t *parser = NULL;
    su_home_t *home = su_home_new(sizeof(*home));
    pc_media_desc_t peer_desc;
    bool ice_found;
    mb_status_t status;
    //pc_local_media_desc_t local_desc;

    /* determine the participant from the socket id */
    data = json_object_get(msg, "data");
    if (!json_is_object(data)) {

        fprintf(stderr, "Error: extracting data from json string\n");
        return MB_INVALID_PARAMS;
    }

    peer_id = json_object_get(data, "socketId");
    if (!json_is_string(peer_id)) {

        fprintf(stderr, "Error: extracting sdp data from json string\n");
        return MB_INVALID_PARAMS;
    }

    id = json_string_value(peer_id);

    fprintf(stderr, "Peer Socket ID: %s\n", id);

    /* make sure this is a known peer, before answering */
    p = livecast_utils_search_participant(s, id);
    if (p == NULL) {
        fprintf(stderr, "Unknown participant id %s. Ignoring the offer\n", id);
        return MB_INVALID_PARAMS;
    }
 
    fprintf(stderr, "Found the rtc participant [id=%s] for the received media\n", p->id);

    /* now extract the sdp */
    sdp_outer = json_object_get(data, "sdp");
    if (!json_is_object(sdp_outer)) {

        fprintf(stderr, "Error: extracting data from json string\n");
        return MB_INVALID_PARAMS;
    }

    sdp_inner = json_object_get(sdp_outer, "sdp");
    if (!json_is_string(sdp_inner)) {

        fprintf(stderr, "Error: extracting data from json string\n");
        return MB_INVALID_PARAMS;
    }

    sdp_buf = json_string_value(sdp_inner);

    fprintf(stderr, "Got SDP: %s\n", sdp_buf);

    /* parse the sdp */
    parser = sdp_parse(home, sdp_buf, strlen(sdp_buf), 0);
    if (!sdp_session(parser)) {
        printf("SDP parsing error: %s\n", sdp_parsing_error(parser));
        return MB_INVALID_PARAMS;
    }

    s->tx_sdp = sdp_session(parser);
    if (s->tx_sdp == NULL) {
        printf("SDP parsing error2: %s\n", sdp_parsing_error(parser));
        return MB_INVALID_PARAMS;
    }

    /* extract peerconn media parameters from peer sdp */
    status = livecast_utils_extract_pc_params_from_sdp(
                                    p, s->tx_sdp, &peer_desc, &ice_found);
    if (status != MB_OK) {
        printf("Error while extrcting peer conn params from peer sdp\n");
        return status;
    }

    fprintf(stderr, "PEER CONNECTION PARAMS extraction done\n");

    memset(&p->local_desc, 0, sizeof(p->local_desc));
    status = livecast_utils_create_local_pc_description(p);
    if (status != MB_OK) {
        printf("Error while creating local media params\n");
        return status;
    }

    /* create peerconn session */
    status = pc_create_session((handle)p, &p->pc);
    if (status != MB_OK) {
        printf("Unable to create peerconn session: %d\n", status);
        return status;
    }

    /* set local media description */
    status = pc_set_local_media_description(p->pc, &p->local_desc);
    if (status != MB_OK) {
        printf("Settng of remote sdp failed\n");
        return status;
    }

    /* set the peer media description */
    status = pc_set_remote_media_description(p->pc, &peer_desc);
    if (status != MB_OK) {
        printf("Settng of remote sdp failed\n");
        return status;
    }

#if 0
    /* sometimes trickled ice candidates get appended to the sdp */
    if (ice_found == true) {
        status = mb_extract_appended_ice_candidates_from_sdp(b_sdp);
    }
#endif

    return MB_OK;
}



mb_status_t rtcmedia_process_ice_candidate(json_t *msg) {

    char *id, *ice;
    int cnt, ice_label;
    json_t *data, *peer_id, *cand, *label;
    rtc_participant_t *p;
    rtc_bcast_session_t *s = &g_session;
    pc_ice_cand_t c;
    char transport[12], type[32];
    mb_status_t status;

    /* determine the participant from the socket id */
    data = json_object_get(msg, "data");
    if (!json_is_object(data)) {

        fprintf(stderr, "Error: extracting data from json string\n");
        return MB_INVALID_PARAMS;
    }

    peer_id = json_object_get(data, "socketId");
    if (!json_is_string(peer_id)) {

        fprintf(stderr, "Error: extracting sdp data from json string\n");
        return MB_INVALID_PARAMS;
    }

    id = json_string_value(peer_id);

    fprintf(stderr, "Peer Socket ID: %s\n", id);

    /* make sure this is a known peer, before answering */
    p = livecast_utils_search_participant(s, id);
    if (p == NULL) {
        fprintf(stderr, "Unknown participant id %s. Ignoring the offer\n", id);
        return MB_INVALID_PARAMS;
    }
 
    fprintf(stderr, "Found the rtc participant [id=%s] for the received media\n", p->id);

    if (!p->pc) {
        fprintf(stderr, "PeerConn handle NULL. "\
                "Ignoring received trickled ice candidate\n");
        return MB_INVALID_PARAMS;
    }

    /*
     * This will only work with Chrome (and Opera) probably for now
     * Since Chrome uses BUNDLE and rtcp-mux, we discard any ICE candidate with
     * a label anything other than "label" = "0".
     * We can add more content here later to make it intelligent and not
     * use the hack!
     */
    label = json_object_get(data, "label");
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

    while((ice = strstr(ice, "candidate:")) != NULL) {
    
        memset(&c, 0, sizeof(c));

        ice += 12;

        cnt = sscanf(ice, "%s %d %s %lld %s %d typ %s", 
                c.cand.foundation, &c.cand.component_id, transport, 
                &c.cand.priority, c.cand.ip_addr, &c.cand.port, type);
        if (cnt != 7) {

            fprintf(stderr, "Invalid ICE candidate line. Wrong no of params?\n");
            return MB_INVALID_PARAMS;
        }

        if (strncmp(type, "host", 4) == 0)
            c.cand.cand_type = ICE_CAND_TYPE_HOST;
        else if (strncmp(type, "srflx", 5) == 0)
            c.cand.cand_type = ICE_CAND_TYPE_SRFLX;
        else if (strncmp(type, "relay", 5) == 0)
            c.cand.cand_type = ICE_CAND_TYPE_RELAYED;
        else {
            fprintf(stderr, "Error: invalid candidate type '%s'", type);
            return MB_INVALID_PARAMS;
        }

        if (strncmp(transport, "udp", 3) == 0)
            c.cand.protocol = ICE_TRANSPORT_UDP;
        else if (strncmp(transport, "tcp", 3) == 0)
            c.cand.protocol = ICE_TRANSPORT_TCP;
        else {
            fprintf(stderr, "Invalid Unknown transport %s\n", transport);
            return MB_INVALID_PARAMS;
        }

        c.cand.ip_addr_type = STUN_INET_ADDR_IPV4; /* TODO; hard code */

        c.eoc = false; /* TODO; hardcode */

        /*
         * This will only work with Chrome (and Opera) probably for now.
         * Chrome makes use of rtcp-mux to send both rtp and rtcp multiplexed 
         * into the same transport port. So effectively there is only one ICE 
         * media stream with only one component. So we will have to pick out 
         * any ice candidates with component value of other than 1
         */
        if (c.cand.component_id != 1) {

            fprintf(stderr, "Discarding ICE candidate "\
                    "with component value of %d\n", c.cand.component_id);
            continue;
        }

        /*
         * Chrome and probably other implementations send TCP ICE candidates.
         * We do not support ICE-TCP, so discard any candidate information
         * that is not of type UDP.
         */
        if (c.cand.protocol != ICE_TRANSPORT_UDP) {

            fprintf(stderr, "Discarding ICE candidate "\
                    "with non-UDP transport protocol: %d\n", c.cand.protocol);
            continue;
        }

        status = pc_set_remote_ice_candidate(p->pc, &c);
        if (status != MB_OK) {
            printf("Settng of remote ice candidate failed\n");
            return status;
        }
    }

    return MB_OK;
}



mb_status_t rtcmedia_add_new_participant(json_t *msg) {

    char *id;
    json_t *data, *r_id;
    rtc_bcast_session_t *s = &g_session;
    rtc_participant_t *p;
    mb_status_t status;

    data = json_object_get(msg, "data");
    if (!json_is_object(data)) {

        fprintf(stderr, "Error: extracting data from json object\n");
        return MB_INVALID_PARAMS;
    }

    r_id = json_object_get(data, "socketId");
    if (!json_is_string(r_id)) {

        fprintf(stderr, "Error: extracting socket id from json string\n");
        return MB_INVALID_PARAMS;
    }

    id = json_string_value(r_id);
    if (!id) {

        fprintf(stderr, "Error: Getting string parameter value\n");
        return MB_INVALID_PARAMS;
    }

    /* should we search and make sure the new id is not already present? */

    p = livecast_utils_get_new_receiver(s);
    if (!p) {

        fprintf(stderr, "Ran out of receiver contexts. Ignore participant\n");
        return MB_NO_RESOURCE;
    }

    p->id = strdup(id);

    /* this participant is the broadcaster? */
    p->is_broadcaster = false;
    p->session = s;
    p->intra_frame_requested = false;

    fprintf(stderr, "New participant created with receiver id: %s\n", p->id);

    return MB_OK;
}



mb_status_t rtcmedia_remove_participant(json_t *msg) {

    char *id;
    json_t *data, *r_id;
    rtc_bcast_session_t *s = &g_session;
    rtc_participant_t *p;
    mb_status_t status;

    data = json_object_get(msg, "data");
    if (!json_is_object(data)) {

        fprintf(stderr, "Error: extracting data from json object\n");
        return MB_INVALID_PARAMS;
    }

    r_id = json_object_get(data, "socketId");
    if (!json_is_string(r_id)) {

        fprintf(stderr, "Error: extracting socket id from json string\n");
        return MB_INVALID_PARAMS;
    }

    id = json_string_value(r_id);
    if (!id) {

        fprintf(stderr, "Error: Getting string parameter value\n");
        return MB_INVALID_PARAMS;
    }

    p = livecast_utils_search_participant(s, id);
    if (p == NULL) {
        fprintf(stderr, "Unknown participant id %s. Ignoring \n", id);
        return MB_INVALID_PARAMS;
    }

    if (p->pc) {
        status = pc_destroy_session(p->pc);
        if (status != MB_OK) {
            fprintf(stderr, "Destroying of peerconn failed\n");
        }
    }

    free(p->id);
    memset(p, 0, sizeof(rtc_participant_t));

    s->cur_rx_count -= 1;

    return MB_OK;
}



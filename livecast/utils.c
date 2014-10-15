
#include <stdio.h>
#include <stdint.h>

#include <sys/epoll.h>

#include <sdp.h>

#include <jansson.h>

#include <mb_types.h>
#include <stun_base.h>

#include <ice_api.h>
#include <pc.h>

#include <livecast.h>


extern rtc_bcast_session_t g_session;
extern char g_local_ip[];
extern int g_epfd;
extern char cert_fp[];

mb_status_t livecast_utils_create_local_pc_description(rtc_participant_t *p) {

    uint32_t i = 0;
    int ret, new_fd, port;
    char *ptr, *fp = cert_fp;
    struct epoll_event event;
    unsigned char temp[16] = {0};
    pc_local_media_desc_t *desc = &(p->local_desc);

    memset(desc, 0, sizeof(pc_media_desc_t));

    desc->dtls_key_type = PC_SHA256;
    desc->role = PC_DTLS_ACTIVE;

    while(*fp) {
        if (*fp == ':') { fp++; continue; }
        desc->fp_key[i] = *fp;
        fp++; i++;

        if (i >= MAX_DTLS_FINGERPRINT_KEY_LEN) break;
    }

    if (p->is_broadcaster == true)
        desc->dir = PC_MEDIA_RECVONLY;
    else
        desc->dir = PC_MEDIA_SENDONLY;

    if (platform_get_random_data(temp, 16) == false) {

        printf("Generating random ice username failed\n");
        return MB_INT_ERROR;
    }

    ptr = desc->ice_ufrag;
    for (i = 0; i < 8; i++, ptr += 2) {
        sprintf(ptr, "%02x", temp[i]);
    }

    if (platform_get_random_data(temp, 16) == false) {

        printf("Generating random ice password failed\n");
        return MB_INT_ERROR;
    }

    ptr = desc->ice_pwd;
    for (i = 0; i < 12; i++, ptr += 2) {
        sprintf(ptr, "%02x", temp[i]);
    }
    strncpy(desc->ice_options, "trickle", PC_ICE_OPTIONS_LEN);

    desc->num_comps = 1;

    new_fd = mb_get_local_bound_port(&port);

    strcpy((char *)desc->host_cands[0].addr.ip_addr, g_local_ip);
    desc->host_cands[0].addr.port = port;
    desc->host_cands[0].addr.host_type = MB_INET_ADDR_IPV4;

    desc->host_cands[0].protocol = MB_TRANSPORT_UDP;
    desc->host_cands[0].local_pref = 65535;
    desc->host_cands[0].comp_id = 1; //RTP_COMPONENT_ID;

    desc->host_cands[0].transport_param = (handle) new_fd;

    printf("############ Bcast MEDIA UDP socket: %d\n", new_fd);

    /* add the port to epoll */
    event.data.ptr = p;
    printf("Added RX to epoll CTL with data ptr %p\n", p);
    event.events = EPOLLIN; // | EPOLLET;
    ret = epoll_ctl(g_epfd, EPOLL_CTL_ADD, new_fd, &event);
    if (ret == -1) {
        perror("epoll_ctl");
        fprintf(stderr, "EPOLL Add operation returned error\n");
        return 1;
    }

    p->fd = new_fd;

    return MB_OK;
}


rtc_participant_t* livecast_utils_search_participant(
                                        rtc_bcast_session_t *s, char *id) {

    int i;
    rtc_participant_t *p;

    if ((s->tx.id) && (strncmp(s->tx.id, id, strlen(id)) == 0))
        return &(s->tx);

    for (i = 0; i < MB_LIVECAST_MAX_RECEIVERS; i++) { 

        p = &s->rx[i];
        if ((p->id) && (strncmp(p->id, id, strlen(id)) == 0))
            return p;
    }

    return NULL;
}


mb_status_t livecast_utils_extract_pc_params_from_sdp(rtc_participant_t *p, 
               sdp_session_t *sdp, pc_media_desc_t *pc_media, bool *ice_found) {

    sdp_media_t *media;
    sdp_attribute_t *attr;
    rtc_bcast_session_t *s = p->session;

    memset(pc_media, 0, sizeof(pc_media_desc_t));

    *ice_found = false;

    for(media = sdp->sdp_media; media; media = media->m_next) {
        for(attr = media->m_attributes; attr; attr = attr->a_next) {
            
            //printf("%s: [%s]\n", attr->a_name, attr->a_value);

            if (strncasecmp(attr->a_name, "candidate", 9) == 0) {

                printf("Candidate attribute received: Len %d TODO %s\n", 
                                    strlen(attr->a_value), attr->a_value);
                *ice_found = true;
            }
            else if (strncasecmp(attr->a_name, "ice-ufrag", 9) == 0) {
                strncpy(pc_media->ice_ufrag, attr->a_value, PC_ICE_MAX_UFRAG_LEN);
            }
            else if (strncasecmp(attr->a_name, "ice-pwd", 7) == 0) {
                strncpy(pc_media->ice_pwd, attr->a_value, PC_ICE_MAX_PWD_LEN);
            }
            else if (strncasecmp(attr->a_name, "ice-options", 11) == 0) {
                strncpy(pc_media->ice_options, attr->a_value, PC_ICE_OPTIONS_LEN);
            }
            else if (strncasecmp(attr->a_name, "ssrc-group", 10) == 0) {

                /* extract only for the broadcaster */
                if (p->is_broadcaster == true) {

                    if (media->m_type == sdp_media_video) {
                        char *token = strtok((char *)attr->a_value, " ");

                        token = strtok(NULL, " ");
                        s->tx_vid_ssrc1 = (uint32_t) strtoul(token, NULL, 10);

                        token = strtok(NULL, "\r\n");
                        s->tx_vid_ssrc2 = (uint32_t) strtoul(token, NULL, 10);
                    }
                }
            }
            else if (strncasecmp(attr->a_name, "ssrc", 4) == 0) {
                if (p->is_broadcaster == true) {
                    /* extract the ssrc parameters from broadcaster offer */
                    if (media->m_type == sdp_media_audio)
                        s->tx_aud_ssrc = 
                            (uint32_t) strtoul(attr->a_value, NULL, 10);
                    else if (media->m_type == sdp_media_video)
                        //g_video_ssrc1 = 
                            //(uint32_t) strtoul(attr->a_value, NULL, 10);
                        ;
                    else
                        s->tx_app_ssrc = 
                            (uint32_t) strtoul(attr->a_value, NULL, 10);
                }
            }
            else if (strncasecmp(attr->a_name, "fingerprint", 11) == 0) {

                /* TODO: should use strtok_r */
                char *token = strtok((char *)attr->a_value, " ");
                if (strncasecmp(token, "sha-256", 7) == 0) {
                    pc_media->dtls_key_type = PC_SHA256;
                }
                else if (strncasecmp(token, "sha-1", 5) == 0) {
                    pc_media->dtls_key_type = PC_SHA1;
                }
                else {
                    printf("Unknown fingerprint key type: %s\n", token);
                }

                while((token = strtok(NULL, " "))) {
                
                    strncpy(pc_media->fp_key, token, MAX_DTLS_FINGERPRINT_KEY_LEN);
                }

            }
            else if (strncasecmp(attr->a_name, "setup", 5) == 0) {
                if (strncasecmp(attr->a_value, "active", 6) == 0) {
                    pc_media->role = PC_DTLS_ACTIVE;
                }
                else if (strncasecmp(attr->a_value, "passive", 7) == 0) {
                    pc_media->role = PC_DTLS_PASSIVE;
                }
                else if (strncasecmp(attr->a_value, "actpass", 7) == 0) {
                    pc_media->role = PC_DTLS_ACTPASS;
                }
                else if (strncasecmp(attr->a_value, "holdconn", 8) == 0) {
                    pc_media->role = PC_DTLS_HOLDCONN;
                }
                else {
                    printf("Unknown setup attribute: %s\n", attr->a_value);
                }
            }
        }
    }

    return MB_OK;
}



rtc_participant_t* livecast_utils_get_new_receiver(rtc_bcast_session_t *s) {

    int32_t i;
    rtc_participant_t *p;

    if (s->cur_rx_count >= MB_LIVECAST_MAX_RECEIVERS) {
        fprintf(stderr, "Have already reached max number of receivers\n");
        return NULL;
    }

    for (i = 0; i < MB_LIVECAST_MAX_RECEIVERS; i++) {
        p = &s->rx[i];

        if(!p->id) break;
    }

    if (i == MB_LIVECAST_MAX_RECEIVERS) return NULL;

    s->cur_rx_count += 1;

    return p;
}



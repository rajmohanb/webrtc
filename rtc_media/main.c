#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include <sdp.h>

#include <platform_api.h>

#include <mb_types.h>
#include <stun_base.h>

#include <ice_api.h>

#include <pc.h>

#include <rtc_media.h>


#define MB_MAX_SDP_SIZE     3000
#define SIGNAL_SERVER_IP    "127.0.0.1"
#define SIGNAL_SERVER_PORT  4096
#define EPOLL_MAX_EVENTS    128


static rtc_bcast_session_t g_session; /* the lone global session */
static int g_epfd, g_sigfd, g_timerfd;
static int pc_port = 51111;
static char local_ip[48] = "10.1.71.170";
static mb_log_level_t g_log_sev = MBLOG_CRITICAL;
static char cert_fp[] = "62:90:01:9c:2b:f3:1a:31:8b:f9:b9:7e:11:b3:41:77:e9:e2:46:8e:d5:8c:a4:a8:62:38:ef:38:e5:20:e5:fa";
static char *log_levels[] =
{
    "MBLOG_EMERG",
    "MBLOG_ALERT",
    "MBLOG_CRITICAL",
    "MBLOG_ERROR",
    "MBLOG_WARNING",
    "MBLOG_NOTICE",
    "MBLOG_INFO",
    "MBLOG_DEBUG",
};
static pc_local_media_desc_t local_desc;


void app_log(stun_log_level_t level,
        char *file_name, uint32_t line_num, char *format, ...)
{
    char buff[500];
    va_list args;
    int relative_time;
    static struct timeval init = { 0, 0 };
    struct timeval now;

    if (level > g_log_sev) return;

    if(init.tv_sec == 0 && init.tv_usec == 0)
        gettimeofday(&init, NULL);

    gettimeofday(&now, NULL);

    relative_time = 1000 * (now.tv_sec - init.tv_sec);
    if (now.tv_usec - init.tv_usec > 0)
        relative_time = relative_time + ((now.tv_usec - init.tv_usec) / 1000);
    else
        relative_time = relative_time - 1 + ((now.tv_usec - init.tv_usec) / 1000);


    va_start(args, format );
    sprintf(buff, "| %s | %i msec <%s: %i> %s\n", 
            log_levels[level], relative_time, file_name, line_num, format);
    vprintf(buff, args );
    va_end(args );
}


static void read_sdp_from_file(char *filename, char *buf, int *buf_len) {

    int fd;
    ssize_t bytes;
    struct stat file_stats;

    /* get file size */
    if (stat(filename, &file_stats) != 0) {
        *buf_len = 0;
        perror("stat ");
        printf("SDP file does not exist: %s\n", filename);
        return;
    }

    if (file_stats.st_size > *buf_len) {
        printf("SDP contents in file larger than buf size: %d\n", 
                (int)file_stats.st_size);
        *buf_len = 0;
        return;
    }

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open: ");
        printf("Unable to open the SDP file\n");
        *buf_len = 0;
        return;
    }

    bytes = read(fd, (void *)buf, *buf_len);
    if (bytes == -1) {
        perror("SDP read: ");
        printf("Error while reading SDP from file: %s\n", filename);
        *buf_len = 0;
        return;
    }

    *buf_len = bytes;
    return;
}


mb_status_t mb_determine_rtp_session_count_from_sdp(
                            sdp_session_t *sdp, int *m_count) {

    return MB_OK;
}



mb_status_t rtcmedia_process_ice_description(char *buf, int len) {

    int cnt;
    pc_ice_cand_t c;
    char transport[12], type[32], *ice = buf;
    mb_status_t status;

    fprintf(stderr, "ICE message of len [%d]=> %s\n", len, buf);

    while((ice = strstr(ice, "a=candidate:")) != NULL) {
    
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
         * Hack!
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
         * Hack!
         * Chrome and probably other implementations send TCP ICE candidates.
         * We do not support ICE-TCP, so discard any candidate information
         * that is not of type UDP.
         */
        if (c.cand.protocol != ICE_TRANSPORT_UDP) {

            fprintf(stderr, "Discarding ICE candidate "\
                    "with non-UDP transport protocol: %d\n", c.cand.protocol);
            continue;
        }

        status = pc_set_remote_ice_candidate(g_session.pc, &c);
        if (status != MB_OK) {
            printf("Settng of remote ice candidate failed\n");
            return status;
        }
    }

    return MB_OK;
}



mb_status_t mb_extract_appended_ice_candidates_from_sdp(sdp_session_t *sdp) {

    sdp_media_t *media;
    sdp_attribute_t *attr;

    for(media = sdp->sdp_media; media; media = media->m_next) {
        for(attr = media->m_attributes; attr; attr = attr->a_next) {
            
            //printf("%s: [%s]\n", attr->a_name, attr->a_value);

            if (strncasecmp(attr->a_name, "candidate", 9) == 0) {
                char icedesc[128] = {0};
                printf("Candidate attribute received: Len %d TODO %s\n", 
                                    strlen(attr->a_value), attr->a_value);
                snprintf(icedesc, 128, "a=candidate:%s", attr->a_value);
                rtcmedia_process_ice_description(icedesc, strlen(icedesc));
            }
        }
    }

    return MB_OK;
}
 


mb_status_t mb_extract_pc_params_from_sdp(
        sdp_session_t *sdp, pc_media_desc_t *pc_media, bool *ice_found) {

    sdp_media_t *media;
    sdp_attribute_t *attr;

    memset(pc_media, 0, sizeof(pc_media_desc_t));

    *ice_found = false;

    for(media = sdp->sdp_media; media; media = media->m_next) {
        for(attr = media->m_attributes; attr; attr = attr->a_next) {
            
            //printf("%s: [%s]\n", attr->a_name, attr->a_value);

            if (strncasecmp(attr->a_name, "candidate", 9) == 0) {
                char icedesc[128] = {0};
                printf("Candidate attribute received: Len %d TODO %s\n", 
                                    strlen(attr->a_value), attr->a_value);
                *ice_found = true;
#if 0
                snprintf(icedesc, 128, "a=candidate:%s", attr->a_value);
                rtcmedia_process_ice_description(icedesc, strlen(icedesc));
#endif
#if 0 
                rtcmedia_process_ice_description(
                                (char *)attr->a_value, strlen(attr->a_value));
#endif
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
                    int i = 0;
                    while(*token) {
                        if (*token == ':') { token++; continue;}
                        pc_media->fp_key[i] = *token;
                        token++; i++;
                    }
                    //strncpy(pc_media->fp_key, token, MAX_DTLS_FINGERPRINT_KEY_LEN);
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


int mb_get_local_bound_port(void) {

    int sockfd;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(struct sockaddr_in));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        printf("Creation of socket descriptor failed\n");
        return 0;
    }

    rtcmedia_make_socket_non_blocking(sockfd);

    addr.sin_port = htons(pc_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        printf("Binding to port failed\n");
        return 0;
    }

    return sockfd;
}


mb_status_t mb_create_local_pc_description(pc_local_media_desc_t *desc) {

    uint32_t i = 0;
    int ret, new_fd;
    char *fp = cert_fp;
    struct epoll_event event;

    memset(desc, 0, sizeof(pc_media_desc_t));

    desc->dtls_key_type = PC_SHA256;
    desc->role = PC_DTLS_ACTIVE;

    while(*fp) {
        if (*fp == ':') { fp++; continue; }
        desc->fp_key[i] = *fp;
        fp++; i++;

        if (i >= MAX_DTLS_FINGERPRINT_KEY_LEN) break;
    }

#if 0
    if (platform_get_random_data(
                (uint8_t *)desc->ice_ufrag, PC_ICE_MAX_UFRAG_LEN) == false) {

        printf("Generating random ice username failed\n");
        return MB_INT_ERROR;
    }

    if (platform_get_random_data(
                (uint8_t *)desc->ice_pwd, PC_ICE_MAX_PWD_LEN) == false) {

        printf("Generating random ice password failed\n");
        return MB_INT_ERROR;
    }
#else
    strncpy(desc->ice_ufrag, "jsdf7uy7fs7a347fres7", PC_ICE_MAX_UFRAG_LEN);
    strncpy(desc->ice_pwd, "f7uy7fs7cnmzzzzhghfga347fres7", PC_ICE_MAX_PWD_LEN);
#endif
    strncpy(desc->ice_options, "trickle", PC_ICE_OPTIONS_LEN);

    desc->num_comps = 1;

    strcpy((char *)desc->host_cands[0].addr.ip_addr, local_ip);
    desc->host_cands[0].addr.port = pc_port;
    desc->host_cands[0].addr.host_type = MB_INET_ADDR_IPV4;

    desc->host_cands[0].protocol = MB_TRANSPORT_UDP;
    desc->host_cands[0].local_pref = 65535;
    desc->host_cands[0].comp_id = 1; //RTP_COMPONENT_ID;

    new_fd = mb_get_local_bound_port();
    desc->host_cands[0].transport_param = (handle) new_fd;

    printf("############ Bcast MEDIA UDP socket: %d\n", new_fd);

    /* add the port to epoll */
    event.data.ptr = &g_session;
    event.events = EPOLLIN; // | EPOLLET;
    ret = epoll_ctl(g_epfd, EPOLL_CTL_ADD, new_fd, &event);
    if (ret == -1) {
        perror("epoll_ctl");
        fprintf(stderr, "EPOLL Add operation returned error\n");
        return 1;
    }

    g_session.bcast_fd = new_fd;

    return MB_OK;
}



mb_status_t mb_create_send_trickle_ice_candidate(ice_cand_params_t *c) {

    int len, len1;
    char iceattr[128] = {0};
    char iceattr1[128] = {0};

    printf("**************** >>>>>>>>>>>>>>  GOT TRICKLE CANDIDATE %d\n", c->cand_type);

    if (c->cand_type == ICE_CAND_TYPE_SRFLX) {

        /* in our case, transport is always UDP for now TODO; */
        /* in our case, candidate type is always HOST for now TODO; */
        len = snprintf(iceattr, 128, "a=candidate:%s %d udp %lld %s %d typ "\
                "srflx raddr %s rport %d", c->foundation, c->component_id, 
                c->priority, c->ip_addr, c->port, c->rel_addr, c->rel_port);

        len1 = snprintf(iceattr1, 128, "a=candidate:%s %d udp %lld %s %d typ "\
                "srflx raddr %s rport %d", c->foundation, (c->component_id+1), 
                c->priority, c->ip_addr, c->port, c->rel_addr, c->rel_port);

    } else if (c->cand_type == ICE_CAND_TYPE_RELAYED) {

        /* in our case, transport is always UDP for now TODO; */
        /* in our case, candidate type is always HOST for now TODO; */
        len = snprintf(iceattr, 128, "a=candidate:%s %d udp %lld %s %d typ "\
                "relay raddr %s rport %d", c->foundation, c->component_id, 
                c->priority, c->ip_addr, c->port, c->rel_addr, c->rel_port);

        len1 = snprintf(iceattr1, 128, "a=candidate:%s %d udp %lld %s %d typ "\
                "relay raddr %s rport %d", c->foundation, (c->component_id+1), 
                c->priority, c->ip_addr, c->port, c->rel_addr, c->rel_port);
    }

    printf("Trickle ICE Message of length [%d] : send to peer:\n%s\n", 
                                                                len, iceattr);

    /* send to signaling server */
    len = send(g_sigfd, iceattr, len, 0);
    if (len == -1) {
        perror("send ");
        fprintf(stderr, "Error while sending answer to signaling server\n");
        return MB_TRANSPORT_FAIL;
    }

    printf("Trickle ICE Message of length [%d] : send to peer:\n%s\n", 
                                                                len1, iceattr1);
    /* send to signaling server */
    len1 = send(g_sigfd, iceattr1, len1, 0);
    if (len1 == -1) {
        perror("send ");
        fprintf(stderr, "Error while sending answer to signaling server\n");
        return MB_TRANSPORT_FAIL;
    }

    return MB_OK;
}



mb_status_t mb_create_send_answer(pc_local_media_desc_t *l, ice_cand_params_t *c)
{
    sdp_parser_t *parser = NULL;
    su_home_t home[1] = { SU_HOME_INIT(home) };
    sdp_session_t *sdp;
    char sdp_buf[4096] = {0};
    uint32_t sdpbuf_len = 4096;
    sdp_media_t *media;
    sdp_attribute_t *attr;
    sdp_printer_t *printer;

    /* read sdp template from file */
    read_sdp_from_file("mb_answer", sdp_buf, (int *)&sdpbuf_len);
    if (sdpbuf_len == 0) {
        printf("Error while reading SDP. Bailing out ...\n");
        return -1;
    }

    /* parse the sdp */
    parser = sdp_parse(home, sdp_buf, sdpbuf_len, 0);

    sdp = sdp_session(parser);
    if (sdp == NULL) {
        printf("SDP parsing error: %s\n", sdp_parsing_error(parser));
        return MB_INVALID_PARAMS;
    }

    /* now update the sdp with local media description */
    for(media = sdp->sdp_media; media; media = media->m_next) {
        for(attr = media->m_attributes; attr; attr = attr->a_next) {
            
            //printf("%s: [%s]\n", attr->a_name, attr->a_value);

            if (strncasecmp(attr->a_name, "candidate", 9) == 0) {

                char iceattr[128] = {0};

                /* in our case, transport is always UDP for now TODO; */
                /* in our case, candidate type is always HOST for now TODO; */
                sprintf(iceattr, "%s %d udp %lld %s %d typ host", 
                        c->foundation, c->component_id, c->priority, 
                        c->ip_addr, c->port);
                attr->a_value = strdup(iceattr);
            }
            else if (strncasecmp(attr->a_name, "ice-ufrag", 9) == 0) {
                /* free existing 'attr->a_value' string, memleak? */
                attr->a_value = strdup(l->ice_ufrag);
            }
            else if (strncasecmp(attr->a_name, "ice-pwd", 7) == 0) {
                /* free existing 'attr->a_value' string, memleak? */
                attr->a_value = strdup(l->ice_pwd);
            }
            else if (strncasecmp(attr->a_name, "fingerprint", 11) == 0) {

                int i = 0;
                char *ptr, fp[128] = {0};
                ptr = fp;

                strcpy(ptr, "sha-256 ");
                ptr += 8;

                while(i < MAX_DTLS_FINGERPRINT_KEY_LEN)
                {
                    *ptr = l->fp_key[i];
                    ptr++; i++;
                    *ptr = l->fp_key[i];
                    ptr++; i++;
                    *ptr = ':';
                    ptr++;
                }

                /* remove the ending ':' */
                ptr--; *ptr = 0;

                /* free existing 'attr->a_value' string, memleak? */
                attr->a_value = strdup(fp);
            }
        }
    }

    /* all modifications for this session done */
    sdpbuf_len = 4096;
    printer = sdp_print(NULL, sdp, sdp_buf, sdpbuf_len, 0);
    if (sdp_message(printer)) {

        char *msg = sdp_message(printer);
        uint32_t size = sdp_message_size(printer);

        msg[size] = 0;

        //printf("Message of length [%d] : send to peer:\n%s\n", size, msg);

        /* send to signaling server */
        size = send(g_sigfd, msg, size, 0);
        if (size == -1) {
            perror("send ");
            fprintf(stderr, "Error while sending answer to signaling server\n");
            return MB_TRANSPORT_FAIL;
        }

        /* TODO; is it possible, less size data is sent? loop? */
    }
    else
    {
        fprintf(stderr, "Error while forming the SDP message\n");
        return MB_INT_ERROR;
    }

    return MB_OK;
}



int32_t rtcmedia_make_socket_non_blocking(int sock_fd)
{
    int flags, s;

    flags = fcntl(sock_fd, F_GETFL, 0);
    if (flags == -1)
    {
        perror("fcntl F_GETFL");
        return MB_TRANSPORT_FAIL;
    }

    flags |= O_NONBLOCK;

    s = fcntl(sock_fd, F_SETFL, flags);
    if (s == -1)
    {
        perror("fcntl F_SETFL");
        return MB_TRANSPORT_FAIL;
    }

    return MB_OK;
}



int rtcmedia_connect_to_signaling_server(void) {

    int fd;
    struct sockaddr_in saddr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Creation of socket failed\n");
        return 0;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(SIGNAL_SERVER_PORT);
    saddr.sin_addr.s_addr = inet_addr(SIGNAL_SERVER_IP);

    if (connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)) <  0) {
        fprintf(stderr, "Error: Connecting to signaling server failed\n");
        return 0;
    }

    return fd;
}



mb_status_t rtcmedia_process_media_description(char *buf, int len) {

    sdp_parser_t *parser = NULL;
    su_home_t home[1] = { SU_HOME_INIT(home) };
    pc_media_desc_t peer_desc;
    sdp_session_t *sdp;
    int m_count, comp_count;
    mb_status_t status;
    bool ice_found;

    memset(&local_desc, 0, sizeof(local_desc));

    fprintf(stderr, "Received SDP of len [%d]: %s\n", len, buf);

    /* parse the sdp */
    parser = sdp_parse(home, buf, len, 0);
    if (!sdp_session(parser)) {
        printf("SDP parsing error: %s\n", sdp_parsing_error(parser));
        return MB_INVALID_PARAMS;
    }

    sdp = sdp_session(parser);
    if (sdp == NULL) {
        printf("SDP parsing error\n");
        return MB_INVALID_PARAMS;
    }

    /* extract peerconn media parameters from peer sdp */
    status = mb_extract_pc_params_from_sdp(sdp, &peer_desc, &ice_found);
    if (status != MB_OK) {
        printf("Error while extrcting peer conn params from peer sdp\n");
        return status;
    }

    /* determine how many rtp/ice sessions peer is proposing */
    status = mb_determine_rtp_session_count_from_sdp(sdp, &m_count);
    if (status != MB_OK) {
        printf("Error while extrcting peer conn params from peer sdp\n");
        return status;
    }

    /* TODO; hardcoded */
    m_count = 1;
    comp_count = 1;

    status = mb_create_local_pc_description(&local_desc);
    if (status != MB_OK) {
        printf("Error while creating local media params\n");
        return status;
    }

    /* create peerconn session */
    status = pc_create_session(&g_session.pc);
    if (status != MB_OK) {
        printf("Unable to initialize peerconn library: %d\n", status);
        return status;
    }

    /* set local media description */
    status = pc_set_local_media_description(g_session.pc, &local_desc);
    if (status != MB_OK) {
        printf("Settng of remote sdp failed\n");
        return status;
    }

    /* set the peer media description */
    status = pc_set_remote_media_description(g_session.pc, &peer_desc);
    if (status != MB_OK) {
        printf("Settng of remote sdp failed\n");
        return status;
    }

    /* sometimes trickled ice candidates get appended to the sdp */
    if (ice_found == true) {
        status = mb_extract_appended_ice_candidates_from_sdp(sdp);
    }

    sdp_parser_free(parser);

    return MB_OK;
}



void rtcmedia_process_signaling_msg(int fd) {

    ssize_t count;
    char buf[4096] = {0};

    count = recv(fd, buf, sizeof(buf), 0);
    if (count == 0) {

        fprintf(stderr, "Signaling server has closed the connection\n");
        /* TODO; do we need to do something? remove fd from epoll */
        return;
    }

    //fprintf(stderr, "%s\n", buf);

    if (strstr(buf, "v=0"))  {
        rtcmedia_process_media_description(buf, count);
    } else {
        rtcmedia_process_ice_description(buf, count);
    }

    return;
}



void rtcmedia_process_timer_expiry(int fd) {

    int bytes;
    socklen_t len;
    pc_timer_event_t event;
    mb_status_t status;

    bytes = recvfrom(fd, &event, sizeof(event), 0, NULL, &len);
    if (bytes == -1) {
        perror("recvfrom ");
        fprintf(stderr, "Receiving timer event failed\n");
        return;
    }

    if (bytes != sizeof(event)) {
        fprintf(stderr, "Received timer buffer length wrong?\n");
        return;
    }

    status = pc_inject_timer_event(&event);
    if (status != MB_OK) {
        fprintf(stderr, "Processing of timer event failed: %d\n", status);
    }

    return;
}



void rtcmedia_process_media_msg(rtc_bcast_session_t *s) {

    uint8_t net_buf[1500];
    struct sockaddr_in recvaddr;
    uint32_t addrlen, bytes;
    mb_status_t status;
    pc_rcvd_data_t rx;

    addrlen = sizeof(recvaddr);
    bytes = recvfrom(s->bcast_fd, 
                net_buf, 1500, 0, (struct sockaddr *)&recvaddr, &addrlen);
    if (bytes == -1) return;

    rx.transport_param = (handle) s->bcast_fd;
    rx.buf = net_buf;
    rx.buf_len = bytes;

    rx.src.host_type = MB_INET_ADDR_IPV4;
    rx.src.port = ntohs(recvaddr.sin_port);
    inet_ntop(AF_INET, &recvaddr.sin_addr, 
            (char *)rx.src.ip_addr, (MB_IPADDR_MAX_LEN - 1));
    /* TODO; check return value of inet_ntop() */

    status = pc_inject_data(s->pc, &rx);
    if (status != MB_OK) {

        printf("pc_inject_data() returned error: %d\n", status);
    }

    return;
}



void pc_ice_handler (handle pc, ice_cand_params_t *c) {

    mb_status_t status;
    printf("RTC MEDIA: Received ice candidate of type %d\n", c->cand_type);

    if (c->cand_type == ICE_CAND_TYPE_HOST) {

        /* create and send answer */
        status = mb_create_send_answer(&local_desc, c);
        if (status != MB_OK) {
            printf("Error while creating local media params\n");
            return;
        }

    } else if (c->cand_type == ICE_CAND_TYPE_SRFLX) {

        /* create and send trickle ice candidate */
        status = mb_create_send_trickle_ice_candidate(c);
        if (status != MB_OK) {
            printf("Error while creating and "\
                    "sending server reflexive trickle ice candidate\n");
            return;
        }
    } else if (c->cand_type == ICE_CAND_TYPE_RELAYED) {

        /* create and send trickle ice candidate */
        status = mb_create_send_trickle_ice_candidate(c);
        if (status != MB_OK) {
            printf("Error while creating and "\
                    "sending relayed trickle ice candidate\n");
            return;
        }
    } else {

        printf("Ignoring unknown ice candidate notification: %d\n", c->cand_type);
    }

    return;
}



mb_status_t rtcmedia_setup_timer_socket(void) {

    int s, ret;
    struct sockaddr_in local_addr;
    struct epoll_event event;

    memset(&local_addr, 0, sizeof(local_addr));

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1) {
        fprintf(stderr, "Creation of timer socket failed\n");
        return MB_INT_ERROR;
    }

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(PC_TIMER_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = bind(s, (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (ret == -1) {
        perror("Bind ");
        fprintf(stderr, "Binding to timer socket failed\n");
        return MB_INT_ERROR;
    }

    /* add it to the epoll list */
    event.data.fd = s;
    event.events = EPOLLIN; // | EPOLLET;
    ret = epoll_ctl(g_epfd, EPOLL_CTL_ADD, s, &event);
    if (ret == -1) {
        perror("epoll_ctl");
        fprintf(stderr, "EPOLL Add operation returned error\n");
        close(s);
        return MB_INT_ERROR;
    }

    g_timerfd = s;
    
    return MB_OK;
}



int main(int argc, char **argv) {

    mb_status_t status;
    int ret, i, n;
    struct epoll_event event, *events;

    g_sigfd = rtcmedia_connect_to_signaling_server();
    if (g_sigfd == 0) {
        fprintf(stderr, "Connecting to signaling server failed. Bailing out\n");
        return 1;
    }

    printf("############ Signaling FD client: %d\n", g_sigfd);

    g_epfd = epoll_create1(0);
    if (g_epfd == -1) {
        fprintf(stderr, "Epoll creation failed\n");
        return 1;
    }

    event.data.fd = g_sigfd;
    event.events = EPOLLIN; // | EPOLLET;
    ret = epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_sigfd, &event);
    if (ret == -1) {
        perror("epoll_ctl");
        fprintf(stderr, "EPOLL Add operation returned error\n");
        return 1;
    }

    events = calloc(EPOLL_MAX_EVENTS, sizeof(event));
    if (events == NULL) {
        fprintf(stderr, "Malloc failed\n");
        return 1;
    }

    /* init the socket on which timer events will be received */
    status = rtcmedia_setup_timer_socket();
    if (status != MB_OK) {
        fprintf(stderr, "Creation of timer socket failed\n");
        return -1;
    }

    /* init the media protocol library - not required for sofia sdp */

    /* init peerconn module */
    status = pc_init(pc_ice_handler);
    if (status != MB_OK) {
        printf("Unable to initialize peerconn library: %d\n", status);
        return -1;
    }

    while (1) {

        n = epoll_wait(g_epfd, events, EPOLL_MAX_EVENTS, -1);
        if (n == -1) {
            perror("EPOLL wait ");
            fprintf(stderr, "EPOLL wait returned error\n");
            continue;
        }

        for (i = 0; i < n; i++) {

            if (g_sigfd == events[i].data.fd) {
                rtcmedia_process_signaling_msg(g_sigfd);
            } else if (&g_session == events[i].data.ptr) {
                rtcmedia_process_media_msg(&g_session);
            } else if (g_timerfd == events[i].data.fd) {
                rtcmedia_process_timer_expiry(g_timerfd);
            } else {

                fprintf(stderr, "Error: Unknown message received on epoll\n");
            }
        }
    }

    return 0;
}

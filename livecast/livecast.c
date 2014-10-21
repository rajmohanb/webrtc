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
#include <ifaddrs.h>
#include <errno.h>

#include <sdp.h>

#include <jansson.h>

#include <platform_api.h>

#include <mb_types.h>
#include <stun_base.h>

#include <ice_api.h>

#include <pc.h>

#include <livecast.h>


#define MB_MAX_SDP_SIZE     3000
#define SIGNAL_SERVER_IP    "127.0.0.1"
#define SIGNAL_SERVER_PORT  4096
#define EPOLL_MAX_EVENTS    128

#define PC_PORT_START       49152
#define PC_PORT_END         65535


rtc_bcast_session_t g_session; /* the lone global session */

static int g_sigfd, g_timerfd;
int g_epfd;

char g_local_ip[48] = {0};
static mb_log_level_t g_log_sev = MBLOG_ERROR;
char cert_fp[] = "62:90:01:9c:2b:f3:1a:31:8b:f9:b9:7e:11:b3:41:77:e9:e2:46:8e:d5:8c:a4:a8:62:38:ef:38:e5:20:e5:fa";
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


typedef struct {

    unsigned int version:2;
    unsigned int p:1;
    unsigned int x:1;
    unsigned int cc:4;
    unsigned int m:1;
    unsigned int pt:7;
    unsigned int seqno:16;
    unsigned int ts;
    unsigned int ssrc;
} rtc_media_rtp_hdr_t;


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


static int32_t rtc_media_get_local_ip(char *ip_buf, int buf_len) {

    struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs * ifa = NULL;
    int s, count = 0;
    mb_status_t status = MB_TRANSPORT_FAIL;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (strncmp(ifa->ifa_name, "lo", 2) == 0) continue;
        if (!ifa->ifa_addr) continue;

        /* Note: we consider only the first available IPv4 address now */
        if (ifa->ifa_addr->sa_family == AF_INET) {
            /* copy the address */
            if (inet_ntop(AF_INET,
                    (void *)&(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr),
                    ip_buf, buf_len)) {
                status = MB_OK;
                break;
            }
        } else if (ifa->ifa_addr->sa_family==AF_INET6) {
            printf("Ignoring IPv6 address\n");
        }
    }

    if (ifAddrStruct != NULL) freeifaddrs(ifAddrStruct);

    return status;
}


mb_status_t mb_determine_rtp_session_count_from_sdp(
                            sdp_session_t *sdp, int *m_count) {

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



int mb_get_local_bound_port(int *port) {

    int i, sockfd;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(struct sockaddr_in));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        printf("Creation of socket descriptor failed\n");
        return 0;
    }

    rtcmedia_make_socket_non_blocking(sockfd);

    for (i = PC_PORT_START; i < PC_PORT_END; i++) {

        addr.sin_port = htons(i);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
            printf("Binding to port %d failed\n", i);
            continue;
        }

        fprintf(stderr, "Bound on local port %d and sock fd %d\n", i, sockfd);
        break;
    }

    if (i == PC_PORT_END) {
        fprintf(stderr, "No more free ports available\n");
        *port = 0;
        return 0;
    }

    *port = i;
    return sockfd;
}





mb_status_t mb_create_send_trickle_ice_candidate(
                            rtc_participant_t *p, ice_cand_params_t *c) {

    int n, len, len1;
    char iceattr[128] = {0};
    char iceattr1[128] = {0};
    json_t *cand, *data, *root;
    char *cmd;

    printf("**************** >>>>>>>>>>>>>>  GOT TRICKLE CANDIDATE %d\n", c->cand_type);

    if (c->cand_type == ICE_CAND_TYPE_SRFLX) {

        /* in our case, transport is always UDP for now TODO; */
        len = snprintf(iceattr, 128, "candidate:%s %d udp %lld %s %d typ "\
                "srflx raddr %s rport %d", c->foundation, c->component_id, 
                c->priority, c->ip_addr, c->port, c->rel_addr, c->rel_port);

        len1 = snprintf(iceattr1, 128, "candidate:%s %d udp %lld %s %d typ "\
                "srflx raddr %s rport %d", c->foundation, (c->component_id+1), 
                c->priority, c->ip_addr, c->port, c->rel_addr, c->rel_port);

    } else if (c->cand_type == ICE_CAND_TYPE_RELAYED) {

        /* in our case, transport is always UDP for now TODO; */
        len = snprintf(iceattr, 128, "candidate:%s %d udp %lld %s %d typ "\
                "relay raddr %s rport %d", c->foundation, c->component_id, 
                c->priority, c->ip_addr, c->port, c->rel_addr, c->rel_port);

        len1 = snprintf(iceattr1, 128, "candidate:%s %d udp %lld %s %d typ "\
                "relay raddr %s rport %d", c->foundation, (c->component_id+1), 
                c->priority, c->ip_addr, c->port, c->rel_addr, c->rel_port);
    }

    data = json_object();
    n = json_object_set_new(data, "socketId", json_string(p->id));
    if (n == -1) { printf("FAILURE 3\n"); }

    cand = json_string(iceattr);
    n = json_object_set_new(data, "candidate", cand);
    if (n == -1) { printf("FAILURE 4\n"); }

    json_object_set_new(data, "label", json_integer(0));

    root = json_object();
    n = json_object_set_new(root, "eventName", json_string("send_ice_candidate"));
    if (n == -1) { printf("FAILURE 5\n"); }

    n = json_object_set_new(root, "data", data);
    if (n == -1) { printf("FAILURE 6\n"); }

    cmd = json_dumps(root, JSON_PRESERVE_ORDER);
    if (!cmd) {
        fprintf(stderr, "JSON encoding of message failed\n");
        return MB_INT_ERROR;
    }

    printf("Trickle ICE Message of length [%d] : send to peer:\n%s\n", strlen(cmd), cmd);

    /* send to signaling server */
    len = send(g_sigfd, cmd, strlen(cmd), 0);
    if (len == -1) {
        perror("send ");
        fprintf(stderr, "Error while sending answer to signaling server\n");
        return MB_TRANSPORT_FAIL;
    }

    json_decref(root);
    free(cmd);

#if 0
    printf("Trickle ICE Message of length [%d] : send to peer:\n%s\n", 
                                                                len1, iceattr1);
    /* send to signaling server */
    len1 = send(g_sigfd, iceattr1, len1, 0);
    if (len1 == -1) {
        perror("send ");
        fprintf(stderr, "Error while sending answer to signaling server\n");
        return MB_TRANSPORT_FAIL;
    }
#endif

    return MB_OK;
}


static sdp_attribute_t a0 = 
{ sizeof(a0), NULL, "candidate", "1000584449 1 udp 2122260223 10.1.71.170 33003 typ host"};


mb_status_t mb_create_send_answer(
        rtc_participant_t *p, pc_local_media_desc_t *l, ice_cand_params_t *c) {

    sdp_parser_t *parser = NULL;
    su_home_t home[1] = { SU_HOME_INIT(home) };
    sdp_session_t *sdp;
    char sdp_buf[4096] = {0};
    uint32_t sdpbuf_len = 4096;
    sdp_media_t *media;
    sdp_attribute_t *attr;
    sdp_printer_t *printer;
    int video_ssrc_attr_count = 0;
    rtc_bcast_session_t *s = p->session;

#if 1
    /* read sdp template from file */
    read_sdp_from_file("mb_answer", sdp_buf, (int *)&sdpbuf_len);
    if (sdpbuf_len == 0) {
        printf("Error while reading SDP. Bailing out ...\n");
        return -1;
    }

    /* parse the sdp */
    parser = sdp_parse(home, sdp_buf, sdpbuf_len, 0);

    sdp = sdp_session(parser);
#else
    sdp = sdp_session_dup(home, s->tx_sdp);
    if (sdp == NULL) {
        printf("SDP parsing error: %s\n", sdp_parsing_error(parser));
        return MB_INVALID_PARAMS;
    }
#endif

    /* now update the sdp with local media description */
    for(media = sdp->sdp_media; media; media = media->m_next) {

        /* remove ice-options */
        sdp_attribute_t *iceopt = sdp_attribute_remove(&media->m_attributes, "ice-options");

        /* append ice host candidate */
        sdp_attribute_append(&media->m_attributes, &a0);

        if (p->is_broadcaster == true) {
            media->m_mode = sdp_recvonly;
        } else {
            media->m_mode = sdp_sendonly;
        }
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
            else if (strncasecmp(attr->a_name, "ssrc-group", 10) == 0) {
                char line[150] = {0};
                sprintf(line, "FID %u %u", s->tx_vid_ssrc1, s->tx_vid_ssrc2);

                attr->a_value = strdup(line);
            }
            else if (strncasecmp(attr->a_name, "ssrc", 4) == 0) {

                char line[150] = {0};
                char *t = attr->a_value;
                while(*t != 32) t++;

                t++;

                if (media->m_type == sdp_media_audio)
                    sprintf(line, "%u %s", s->tx_aud_ssrc, t);
                else if (media->m_type == sdp_media_video) {

                    if (video_ssrc_attr_count < 4)
                        sprintf(line, "%u %s", s->tx_vid_ssrc1, t);
                    else
                        sprintf(line, "%u %s", s->tx_vid_ssrc2, t);

                    video_ssrc_attr_count++;
                }
                else
                    sprintf(line, "%u %s", s->tx_app_ssrc, t);

                attr->a_value = strdup(line);
            }
            else if (strncasecmp(attr->a_name, "fingerprint", 11) == 0) {

                int j, i = 0;
                char *ptr, fp[128] = {0};
                ptr = fp;

                strcpy(ptr, "sha-256 ");
                ptr += 8;

                j = strlen(l->fp_key);

                while(i < j)
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
            else if (strncasecmp(attr->a_name, "setup", 5) == 0) {

                /* for everyone, we are dtls client? */
                attr->a_value = strdup("active");
            }
        }
    }

    /* all modifications for this session done */
    sdpbuf_len = 4096;
    printer = sdp_print(NULL, sdp, sdp_buf, sdpbuf_len, 0);
    if (sdp_message(printer)) {

        int n;
        json_t *answer, *desc, *data, *root;
        char *cmd, *msg = sdp_message(printer);
        uint32_t size = sdp_message_size(printer);

        answer = json_object();
        desc = json_string(msg);
        if (desc == NULL) { printf("FAILURE 0\n"); }

        n = json_object_set_new(answer, "sdp", desc);
        if (n == -1) { printf("FAILURE 1\n"); }

        n = json_object_set_new(answer, "type", json_string("answer"));
        if (n == -1) { printf("FAILURE 2\n"); }

        data = json_object();
        n = json_object_set_new(data, "socketId", json_string(p->id));
        if (n == -1) { printf("FAILURE 3\n"); }

        n = json_object_set_new(data, "sdp", answer);
        if (n == -1) { printf("FAILURE 4\n"); }

        root = json_object();
        n = json_object_set_new(root, "eventName", json_string("send_answer"));
        if (n == -1) { printf("FAILURE 5\n"); }

        n = json_object_set_new(root, "data", data);
        if (n == -1) { printf("FAILURE 6\n"); }

        cmd = json_dumps(root, JSON_PRESERVE_ORDER);
        if (!cmd) {
            fprintf(stderr, "JSON encoding of message failed\n");
            return MB_INT_ERROR;
        }

        printf("Message of length [%d] : send to peer:\n%s\n", strlen(cmd), cmd);

        /* send to signaling server */
        size = send(g_sigfd, cmd, strlen(cmd), 0);
        if (size == -1) {
            perror("send ");
            fprintf(stderr, "Error while sending answer to signaling server\n");
            return MB_TRANSPORT_FAIL;
        }

        json_decref(root);
        free(cmd);

        /* TODO; is it possible, less size data is sent? loop? */
        printf("Sent Answer to Signaling of Size: %d\n", strlen(cmd));
    } else {
        fprintf(stderr, "Error while forming the SDP message\n");
        return MB_INT_ERROR;
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
        perror("connect ");
        fprintf(stderr, "Error: Connecting to signaling server failed\n");
        return 0;
    }

    return fd;
}



void rtcmedia_process_signaling_msg(int fd) {

    json_t *root;
    ssize_t count;
    json_error_t error;
    char buf[4096] = {0};
    char *ptr, *value;
    json_t *event;
    mb_status_t status;

    count = recv(fd, buf, sizeof(buf), 0);
    if (count == 0) {

        fprintf(stderr, "Signaling server has closed the connection\n");
        /* TODO; do we need to do something? remove fd from epoll */
        return;
    }

    fprintf(stderr, "%s\n", buf);
    ptr = buf;

    do {
        root = json_loads(ptr, JSON_DISABLE_EOF_CHECK, &error); 
        if (!root) {
            fprintf(stderr, "error while decoding json text received from"\
                    " signaling server. Error: on line %d: %s\n", 
                    error.line, error.text);
            fprintf(stderr, "The string received is : \n%s\n", ptr);
            json_decref(root);
            return;
        }
    
        printf("BUFFER LEN: %d and JSON LOADS POSITION: %d\n", count, error.position);
        ptr += error.position;

        if (!json_is_object(root)) {

            fprintf(stderr, "Error: root is not an object\n");
            fprintf(stderr, "JSON type %d\n", json_typeof(root));
            json_decref(root);
            return;
        }

        event = json_object_get(root, "eventName");
        if (!json_is_string(event)) {

            fprintf(stderr, "error: eventName is not a string\n");
            return;
        }

        value = json_string_value(event);

        printf("Received Event: %s\n", value);

        if (strncasecmp(value, "new_channel", 11) == 0) {
            /* currently, we support only one channel/room, the global one! */
            memset(&g_session, 0, sizeof(rtc_bcast_session_t));

            rtcmedia_process_new_channel_req(root);
        } else if (strncasecmp(value, "receive_ice_candidate", 21) == 0) {
            status = rtcmedia_process_ice_candidate(root);
        } else if (strncasecmp(value, "receive_offer", 13) == 0) {
            status = rtcmedia_process_offer(root);
        } else if (strncasecmp(value, "receive_answer", 14) == 0) {
            //status = rtcmedia_process_answer();
        } else if (strncasecmp(value, "new_peer_connected", 18) == 0) {
            status = rtcmedia_add_new_participant(root);
        } else if (strncasecmp(value, "remove_peer_connected", 21) == 0) {
            status = rtcmedia_remove_participant(root);
        } else {
            fprintf(stderr, 
                    "Unknown event [%s] received from signaling server\n", value);
        }

    } while(count > (ptr-buf));

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



void rtcmedia_process_media_msg(rtc_participant_t *p) {

    uint8_t net_buf[1500];
    struct sockaddr_in recvaddr;
    uint32_t addrlen, bytes;
    mb_status_t status;
    pc_rcvd_data_t rx;
    rtc_bcast_session_t *s = (rtc_bcast_session_t *) p->session;

    addrlen = sizeof(recvaddr);
    bytes = recvfrom(p->fd, 
                net_buf, 1500, 0, (struct sockaddr *)&recvaddr, &addrlen);
    if (bytes == -1) return;

    rx.transport_param = (handle) p->fd;
    rx.buf = net_buf;
    rx.buf_len = bytes;

    rx.src.host_type = MB_INET_ADDR_IPV4;
    rx.src.port = ntohs(recvaddr.sin_port);
    inet_ntop(AF_INET, &recvaddr.sin_addr, 
            (char *)rx.src.ip_addr, (MB_IPADDR_MAX_LEN - 1));
    /* TODO; check return value of inet_ntop() */

    status = pc_inject_received_data(p->pc, &rx);
    if (status != MB_OK) {
        printf("pc_inject_received_data() returned error: %d\n", status);
    }

    return;
}



void pc_ice_handler (handle pc, handle app_handle, ice_cand_params_t *c) {

    mb_status_t status;
    rtc_participant_t *p = (rtc_participant_t *)app_handle;
    printf("RTC MEDIA: Received ice candidate of type %d\n", c->cand_type);

    if (c->cand_type == ICE_CAND_TYPE_HOST) {

        /* create and send answer */
        status = mb_create_send_answer(p, &p->local_desc, c);
        if (status != MB_OK) {
            printf("Error while creating local media params\n");
            return;
        }

        //g_ready = 1;
    } else if (c->cand_type == ICE_CAND_TYPE_SRFLX) {

        /* create and send trickle ice candidate */
        status = mb_create_send_trickle_ice_candidate(p, c);
        if (status != MB_OK) {
            printf("Error while creating and "\
                    "sending server reflexive trickle ice candidate\n");
            return;
        }
    } else if (c->cand_type == ICE_CAND_TYPE_RELAYED) {

        /* create and send trickle ice candidate */
        status = mb_create_send_trickle_ice_candidate(p, c);
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



void pc_incoming_media(handle pc, 
                handle app_handle, uint8_t *buf, uint32_t len) {

    int32_t i;
    mb_status_t status;
    rtc_participant_t *r;
    rtc_participant_t *p = (rtc_participant_t *)app_handle;
    rtc_bcast_session_t *s = p->session;

    if (p->is_broadcaster == true)
        if (s->cur_rx_count == 0)
            return;

    /* pipe it to the other peerconnection */
    for (i = 0; i < MB_LIVECAST_MAX_RECEIVERS; i++) {

        r = &(s->rx[i]);
        if (!r->pc) continue;

        status = pc_send_media_data(r->pc, buf, len);
        if (status != MB_OK) {
            fprintf(stderr, "Sending of broadcast media of len [%d] to receiver failed\n", len);
        }
    }

    return;
}



int main(int argc, char **argv) {

    mb_status_t status;
    int ret, i, j, n;
    struct epoll_event event, *events;
    rtc_participant_t *p;

    status = rtc_media_get_local_ip(g_local_ip, 48);
    if (status != MB_OK) {
        fprintf(stderr, "Error: Unable to determine local interface IP addr\n");
        return 1;
    }

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
    status = pc_init(pc_ice_handler, pc_incoming_media);
    if (status != MB_OK) {
        printf("Unable to initialize peerconn library: %d\n", status);
        return -1;
    }

    while (1) {

        n = epoll_wait(g_epfd, events, EPOLL_MAX_EVENTS, -1);
        if (n == -1) {
            if (errno != EINTR) {
                perror("EPOLL wait ");
                fprintf(stderr, "EPOLL wait returned error\n");
            }
            continue;
        }

        for (i = 0; i < n; i++) {

            if (g_sigfd == events[i].data.fd) {
                rtcmedia_process_signaling_msg(g_sigfd);
            } else if (&g_session.tx == events[i].data.ptr) {
                //printf("epoll notification TX: Data on data ptr %p\n", events[i].data.ptr);
                rtcmedia_process_media_msg(&g_session.tx);
            } else if (g_timerfd == events[i].data.fd) {
                rtcmedia_process_timer_expiry(g_timerfd);
            } else {

                for (j = 0; j < MB_LIVECAST_MAX_RECEIVERS; j++) {
                    p = &g_session.rx[j];
                    if (p == events[i].data.ptr) {
                        rtcmedia_process_media_msg(p);
                        break;
                    }
                }

                if (i == MB_LIVECAST_MAX_RECEIVERS)
                    fprintf(stderr, "Error: Unknown message received on epoll\n");
            }
        }
    }

    return 0;
}

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
//#include <strings.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libwebsockets.h>

#include <jansson.h>

#include <mb_types.h>

#include <rtcsig.h>


#define MAX_SESSIONS        1
#define RTCSIG_LISTEN_PORT  4096

static fd_set r_fds;
static mb_log_level_t g_loglevel = MBLOG_WARNING;
struct libwebsocket_context *context;
int media_server_fd = 0;
static rtcsig_session_t *g_session;
static char *log_levels[] =
{
    "MBLOG_CRITICAL",
    "MBLOG_ERROR",
    "MBLOG_WARNING",
    "MBLOG_INFO",
    "MBLOG_DEBUG",
};



static void rtcsig_handle_media_server_events(int fd) {

    int bytes;
    char buf[4096] = {0};
    mb_status_t status;
    rtcsig_event_t event;

    bytes = recv(media_server_fd, buf, 4096, 0);
    if (bytes == -1) {
        perror("recv ");
        fprintf(stderr, "Error while receiving data from media server\n");
        return;
    }

    if (bytes == 0) {

        fprintf(stderr, "Did the media server close the connection?\n");
        FD_CLR(fd, &r_fds);
        close(fd);
        media_server_fd = 0;
        fprintf(stderr, "Media server closed/lost the connection\n");
        return;
    }


    if (strstr(buf, "v=0"))
        event = RTC_EVENT_LOCAL_MEDIA;
    else if (strstr(buf, "a=candidate"))
        event = RTC_EVENT_LOCAL_ICE_CAND;
    else
        event = RTC_EVENT_MAX;

    if (event == RTC_EVENT_MAX) {
        fprintf(stderr, "Unknown event [%s] received from media server\n", buf);
        return;
    }

    status = rtcsig_session_fsm_inject_msg(
            g_session, event, (handle)buf, (handle)bytes);
    if (status != MB_OK) {
        fprintf(stderr, "Signaling fsm returned error: %d\n", status);
    }

    return;
}


static rtcsig_event_t rtcsig_get_event_from_json(json_t *json) {

    char *value;
    rtcsig_event_t e;
    json_t *event;

    event = json_object_get(json, "eventName");
    if (!json_is_string(event)) {

        fprintf(stderr, "error: eventName is not a string\n");
        return RTC_EVENT_MAX;
    }

    value = json_string_value(event);

    if (strncasecmp(value, "get_peers", 9) == 0) {
        e = RTC_EVENT_PEERS_LIST;
    } else if (strncasecmp(value, "receive_ice_candidate", 21) == 0) {
        e = RTC_EVENT_PEER_ICE_CAND;
    } else if (strncasecmp(value, "receive_offer", 13) == 0) {
        e = RTC_EVENT_PEER_MEDIA;
    } else if (strncasecmp(value, "receive_answer", 14) == 0) {
        e = RTC_EVENT_PEER_MEDIA;
    } else if (strncasecmp(value, "new_peer_connected", 18) == 0) {
        e = RTC_EVENT_NEW_PEER;
    } else if (strncasecmp(value, "remove_peer_connected", 21) == 0) {
        e = RTC_EVENT_DEL_PEER;
    } else {
        e = RTC_EVENT_MAX;
    }

    return e;
}


static int 
callback_webrtc(struct libwebsocket_context *context, 
                struct libwebsocket *wsi, 
                enum libwebsocket_callback_reasons reason, 
                void *user, void *in, size_t len) {

    json_t *root;
    int n;
    rtcsig_event_t event;
    json_error_t error;
    mb_status_t status;
    rtcsig_session_t *session = (rtcsig_session_t *)user;

    switch(reason) {

        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            fprintf(stderr, "Client connected to signaling server\n");

            session->state = RTC_OFFLINE;
            session->wsi = wsi;
            session->ringbuffer_tail = session->ringbuffer_head = 0;

            session->you = session->peer = session->rcvr = NULL;
            
            libwebsocket_callback_on_writable(context, wsi);

            g_session = session;

            break;

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            fprintf(stderr, "Client connection error\n");
            break;

        case LWS_CALLBACK_CLOSED:
            fprintf(stderr, "Connected closed\n");
            g_session = NULL;
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:
            fprintf(stderr, "Client received data\n");
		    fprintf(stderr, "rx %d '%s'\n", (int)len, (char *)in);

            root = json_loads(in, 0, &error); 
            if (!root) {
                fprintf(stderr, "error while decoding json text received from"\
                        " signaling server. Error: on line %d: %s\n", 
                        error.line, error.text);
                json_decref(root);
                break;
            }

            if (!json_is_object(root)) {

                fprintf(stderr, "Error: root is not an object\n");
                fprintf(stderr, "JSON type %d\n", json_typeof(root));
                json_decref(root);
                break;
            }

            event = rtcsig_get_event_from_json(root);
            if (event >= RTC_EVENT_MAX) {
                fprintf(stderr, "Ignoring the received json event\n");
                break;
            }

            status = rtcsig_session_fsm_inject_msg(session, event, root, NULL);
            if (status != MB_OK) {
                fprintf(stderr, "Signaling fsm returned error: %d\n", status);
            }

            /* TODO; decrement root? which scenarios */

            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE:
            fprintf(stderr, "Connection writable now\n");

            if (session->state == RTC_OFFLINE) {

                status = rtcsig_session_fsm_inject_msg(
                                session, RTC_EVENT_SIGNIN, NULL, NULL);
                if (status != MB_OK) {
                    fprintf(stderr, "Signing into the server failed: %d\n", status);
                    fprintf(stderr, "Aborting ...!\n");
                    return 1;
                }
            }

            while (session->ringbuffer_tail != session->ringbuffer_head) {

                n = libwebsocket_write(wsi, 
                        (unsigned char *)session->ringbuffer[session->ringbuffer_tail].payload + 
                        LWS_SEND_BUFFER_PRE_PADDING, 
                        session->ringbuffer[session->ringbuffer_tail].len, 
                        LWS_WRITE_TEXT);

                if (n < 0) {
                    lwsl_err("ERROR %d writing to webrtc socket\n", n);
                    return -1;
                }

                if (n < session->ringbuffer[session->ringbuffer_tail].len) {
                    lwsl_err("webrtc partial write %d vs %d\n", n,
                            session->ringbuffer[session->ringbuffer_tail].len);
                }

                if (session->ringbuffer_tail == (MAX_MESSAGE_QUEUE - 1))
                    session->ringbuffer_tail = 0;
                else
                    session->ringbuffer_tail++;

                free(session->ringbuffer[session->ringbuffer_tail].payload);

                if (lws_send_pipe_choked(wsi)) {
                    libwebsocket_callback_on_writable(context, wsi);
                    break;
                }
            }

            break;

        default:
            break;
    }

    return 0;
}


struct libwebsocket_protocols protocols[] = {
    {
        NULL,
        callback_webrtc,
        sizeof(rtcsig_session_t),
        4096,
    },
    {
        NULL,
        NULL,
        0,
        0
    }
};


void app_log(mb_log_level_t level,
        char *file_name, uint32_t line_num, char *format, ...)
{
    char buff[500];
    va_list args;
    int relative_time;
    static struct timeval init = { 0, 0 };
    struct timeval now;

    if (level > g_loglevel) return;

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



int rtcsig_setup_tcp_server(void) {

    int fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Creation of socket failed\n");
        return 0;
    }

    bzero((char *)&addr, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(RTCSIG_LISTEN_PORT);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Binding to address failed\n");
        return 0;
    }

    listen(fd, 5);

    return fd;
}



int main(int argc, char **argv) {

    int listen_fd, max_fd, fd_count, size;
    int n = 0, ietf_version = -1; /* latest */
    struct lws_context_creation_info info;
    struct libwebsocket *wsi;
    fd_set temp_fds;
    struct timeval timeout;
    struct sockaddr_in caddr;

    memset(&info, 0, sizeof(info));

    fprintf(stderr, "webrtc live broadcast server\n"
            "(C) Copyright 2014 Rajmohan Banavi <rajmohanbanavi@gmail.com>\n");

    /* create the websockets context */
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
#ifndef LWS_NO_EXTENSIONS
    info.extensions = libwebsocket_get_internal_extensions();
#endif
    info.gid = -1;
    info.uid = -1;

    context = libwebsocket_create_context(&info);
    if (context == NULL) {
        fprintf(stderr, "Creating libwebsocket context failed\n");
        return 1;
    }

    /* setup tcp server for communication with media servers */
    listen_fd = rtcsig_setup_tcp_server();
    if (listen_fd <= 0) {
        fprintf(stderr, "Unable to setup TCP server. Bailing out ...!\n");
        return 1;
    }

    FD_ZERO(&r_fds);
    FD_SET(listen_fd, &r_fds);
    max_fd = listen_fd;
    temp_fds = r_fds;

    /* ensure all the client sessions are connected to the server */
    for (n = 0; n < MAX_SESSIONS; n++) {

        fprintf(stderr, "Connecting to signaling server\n");

        wsi = libwebsocket_client_connect(
                context, "127.0.0.1", 8080, 0, "/", "127.0.0.1", "127.0.0.1", 
                protocols[WEBRTC_PROTO_DEFAULT].name, ietf_version);
        if (wsi == NULL) {
            fprintf(stderr, "Connecting to ws server failed\n");
            return MB_TRANSPORT_FAIL;
        }
    }

    /* keep servicing the websockets */
    while(1) {

        temp_fds = r_fds;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        fd_count = select((max_fd+1), &temp_fds, NULL, NULL, &timeout); 
        if (fd_count == -1) {
            perror("Select ");
            fprintf(stderr, "Select returned error\n");
            continue;
        }

        for (n = 0; n < fd_count; n++) {

            if (FD_ISSET(listen_fd, &temp_fds)) {

                size = sizeof(caddr);
                /* connect request from a media server */
                media_server_fd = accept(
                        listen_fd, (struct sockaddr *)&caddr, (socklen_t *)&size);
                if (media_server_fd == -1) {
                    perror("Accept ");
                    fprintf(stderr, "Accepting client connection failed\n");
                    continue;
                }

                fprintf(stderr, "One media server client connected FD: %d\n", media_server_fd); 

                if (media_server_fd > max_fd) max_fd = media_server_fd;
                FD_SET(media_server_fd, &r_fds);
                continue;
            } else if (FD_ISSET(media_server_fd, &temp_fds)) {

                /* handle data from media server */
                rtcsig_handle_media_server_events(media_server_fd);
            } else {

                fprintf(stderr, "select returned event on unknown FD\n");
            }
        }

        n = libwebsocket_service(context, 10);

        /* check for any connect attempts from media servers */

        if (n < 0) continue;
    }

    return 0;
}

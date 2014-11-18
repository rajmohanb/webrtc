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

/* openssl */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* srtp */
#include <srtp/err.h>
#include <srtp/srtp.h>

#include <mb_types.h>

#include <dtls_srtp.h>

#include <dtls_srtp_int.h>


#define SSL_WHERE_INFO(ssl, w, flag, msg) {                 \
    if (w & flag) {                                         \
        printf("+ %s: ", "rajmohan");                       \
        printf("%20.20s", msg);                             \
        printf(" - %30.30s ", SSL_state_string_long(ssl));  \
        printf(" - %5.10s ", SSL_state_string(ssl));        \
        printf("\n");                                       \
    }                                                       \
}


dtls_srtp_instance_t g_dtls_srtp;


int pc_dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    fprintf(stderr, "pc_dtls_verify_callback\n");
    return 1;
}



void dtls_srtp_send_any_pending_data(dtls_srtp_session_t *s) {

    int sent, pending, buf_len;
    pending = BIO_ctrl_pending(s->sink_bio);
    printf("SSL SINK BIO PENDING BYTES: %d\n", pending);

    if (pending) {
        if (s->sent_msg) {
            /* send(retransmit) before free? */
            free(s->sent_msg);
        }

        s->sent_msg = calloc(1, pending);
        s->sent_msg_len = pending;
        buf_len = BIO_read(s->sink_bio, s->sent_msg, pending);

        sent = g_dtls_srtp.cb(s, s->sent_msg, buf_len, s->app_handle);

        if (sent < buf_len) {
            fprintf(stderr, "Error sending DTLS data. Sent "\
                    "only %d bytes against given %d bytes\n", sent, buf_len);
            /* TODO; what do we do now? error? */
        } else {
            //fprintf(stderr, "Sent DTLS data of len %d\n", sent);
        }

        /* no retransmission for application data. Only for handshake! */
        if (s->state != DTLS_SRTP_READY) {

            /* 
             * minimal retransmission support for dtls handshake 
             * messages as per RFC 4347.
             */
            s->timer_id = g_dtls_srtp.timer_start_cb(DTLS_RETX_TIMER_VAL, s);
            if (s->timer_id) {
                fprintf(stderr, "Started DTLS retransmission "\
                        "timer for %d duration\n", DTLS_RETX_TIMER_VAL);
            } else {
                fprintf(stderr, "Starting DTLS retransmission "\
                        "timer for %d duration FAILED\n", DTLS_RETX_TIMER_VAL);
            }
        }
    }

    return;
}


mb_status_t dtls_srtp_init(dtls_srtp_data_send_cb cb, 
                           dtls_srtp_incoming_app_data_cb app_cb, 
                           dtls_srtp_start_timer_cb start_timer_cb, 
                           dtls_srtp_stop_timer_cb stop_timer_cb) {

    const EVP_MD *digest;
    unsigned int n, pos;
    err_status_t err;

    /* initialize the openssl library for dtls */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    /* perform all openssl context initialization */
    /* TODO; Webrtc mandates v1.2? need to check */
    g_dtls_srtp.ctx = SSL_CTX_new(DTLSv1_method());
    if(g_dtls_srtp.ctx == NULL) {
        fprintf(stderr, "SSL Context Initialization failed\n");
        goto PC_ERROR_EXIT2;
    }

    SSL_CTX_set_verify(g_dtls_srtp.ctx, 
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
            pc_dtls_verify_callback);
    /* rfc 5764 sec 4.1 */
    SSL_CTX_set_tlsext_use_srtp(g_dtls_srtp.ctx, "SRTP_AES128_CM_SHA1_80");
    if (SSL_CTX_use_certificate_file(
                g_dtls_srtp.ctx, PC_DTLS_CERT_FILE, SSL_FILETYPE_PEM) != 1) {

        fprintf(stderr, "Error while loading openssl certificate file\n");
        goto PC_ERROR_EXIT2;
    }

    printf("Certificate File: %s\n", PC_DTLS_CERT_FILE); 
    printf("Key File: %s\n", PC_DTLS_KEY_FILE); 

    if (SSL_CTX_use_PrivateKey_file(
                g_dtls_srtp.ctx, PC_DTLS_KEY_FILE, SSL_FILETYPE_PEM) != 1) {

        printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
        fprintf(stderr, "Error while loading openssl key file\n");
        goto PC_ERROR_EXIT2;
    }

    if (SSL_CTX_check_private_key(g_dtls_srtp.ctx) != 1) {
        printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
        fprintf(stderr, "Error while checking and validating of private key\n");
        goto PC_ERROR_EXIT2;
    }

    g_dtls_srtp.cert_bio = BIO_new(BIO_s_file());
    if (g_dtls_srtp.cert_bio == NULL) {
        printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
        fprintf(stderr, "Error while creating new BIO object\n");
        goto PC_ERROR_EXIT2;
    }

    if (BIO_read_filename(g_dtls_srtp.cert_bio, PC_DTLS_CERT_FILE) != 1) {
        printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
        fprintf(stderr, "Reading of certificate failed\n");
        goto PC_ERROR_EXIT2;
    }

    if ((g_dtls_srtp.x = PEM_read_bio_X509(
                        g_dtls_srtp.cert_bio, NULL, 0, NULL)) == NULL) {
        printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
        fprintf(stderr, "Error reading X509 certificate\n");
        goto PC_ERROR_EXIT2;
    }

    digest = EVP_get_digestbyname("sha256");
    X509_digest(g_dtls_srtp.x, digest, g_dtls_srtp.md, &n);
    printf("Length of fingerprint: %d\n", n);
    printf("Fingerprint: ");
    for(pos = 0; pos < n; pos++)
        printf("%02x:", g_dtls_srtp.md[pos]);
    //printf("%02x\n", g_dtls_srtp.md[n]);
    printf("\n");

    if (SSL_CTX_set_cipher_list(g_dtls_srtp.ctx, PC_DTLS_CIPHERS) != 1) {
        fprintf(stderr, "Setting cipher list to SSL CTX failed\n");
        goto PC_ERROR_EXIT2;
    }

    /* initialize the secure rtp stack */
    err = srtp_init();
    if (err) { 
        printf("error: srtp init failed with error code %d\n", err);
        goto PC_ERROR_EXIT2;
    }

    g_dtls_srtp.cb = cb;
    g_dtls_srtp.app_cb = app_cb;
    g_dtls_srtp.timer_start_cb = start_timer_cb;
    g_dtls_srtp.timer_stop_cb = stop_timer_cb;

    return MB_OK;
PC_ERROR_EXIT2:
    /* TODO; free all */
    return MB_INT_ERROR;
}



void dtls_srtp_session_callback(const SSL *ssl, int where, int ret) {

    if (ret == 0) {
        printf("-- dtls_srtp_session_callback: error occured\n");
        return;
    }

    SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");

    return;
}



mb_status_t dtls_srtp_create_session(dtls_setup_role_type_t role, 
            dtls_key_type_t type, int sock, handle app_handle, handle *h_dtls) {

    dtls_srtp_session_t *s;

    /* allocate memory for the new session */
    s = (dtls_srtp_session_t *) calloc(1, sizeof(dtls_srtp_session_t));
    if (s == NULL) {
        fprintf(stderr, "Memory allocation for new DTLS_SRTP session failed\n");
        return MB_MEM_ERROR;
    }

    s->ssl = SSL_new(g_dtls_srtp.ctx);
    if (s->ssl == NULL) {
        fprintf(stderr, "Creation of new SSL structure for session failed\n");
        return MB_INT_ERROR;
    }

    if (SSL_set_ex_data(s->ssl, 0, s) != 1) {
        fprintf(stderr, "Setting of app data to new SSL structure failed\n");
        return MB_INT_ERROR;
    }

    SSL_set_info_callback(s->ssl, dtls_srtp_session_callback);

    /* setup the source/read and sink/write bio */
    s->src_bio = BIO_new(BIO_s_mem());
    if (s->src_bio == NULL) {
        fprintf(stderr, "Creation of source BIO for session failed\n");
        return MB_INT_ERROR;
    }
    BIO_set_mem_eof_return(s->src_bio, -1);

    s->sink_bio = BIO_new(BIO_s_mem());
    if (s->sink_bio == NULL) {
        fprintf(stderr, "Creation of sink BIO for session failed\n");
        return MB_INT_ERROR;
    }
    BIO_set_mem_eof_return(s->sink_bio, -1);

    SSL_set_bio(s->ssl, s->src_bio, s->sink_bio);

    s->role = role;
    if (role == DTLS_ACTIVE) {
        SSL_set_connect_state(s->ssl);
        printf("SSL session role: Connect role\n");
    } else if (role == DTLS_PASSIVE) {
        SSL_set_accept_state(s->ssl);
        printf("SSL session role: Accept role\n");
    }

    s->app_handle = app_handle;
    s->digest_type = type;

    s->state = DTLS_SRTP_INIT;

    *h_dtls = s;

    return MB_OK;

    /* TODO; handle error scenarios and cleanup */
}



mb_status_t dtls_srtp_session_do_handshake(handle h_dtls) {

    int ret;
    dtls_srtp_session_t *s = (dtls_srtp_session_t *)h_dtls;

    ret = SSL_do_handshake(s->ssl);
    printf("SSL_do_handshake : %d\n", ret);
    if (ret != 1) {
        int err = SSL_get_error(s->ssl, ret);
        printf("[%d] SSL_do_handshake: %d\n", ret, err);
        switch(err) {
            case SSL_ERROR_NONE:
                printf("SSL_ERROR_NONE\n");
                break;
            case SSL_ERROR_ZERO_RETURN:
                printf("SSL_ERROR_ZERO_RETURN\n");
                break;
            case SSL_ERROR_WANT_READ:
                printf("SSL_ERROR_WANT_READ\n");
                break;
            case SSL_ERROR_WANT_WRITE:
                printf("SSL_ERROR_WANT_WRITE\n");
                break;
            case SSL_ERROR_WANT_CONNECT:
                printf("SSL_ERROR_WANT_CONNECT\n");
                break;
            case SSL_ERROR_WANT_ACCEPT:
                printf("SSL_ERROR_WANT_ACCEPT\n");
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                printf("SSL_ERROR_WANT_X509_LOOKUP\n");
                break;
            case SSL_ERROR_SYSCALL:
                printf("SSL_ERROR_SYSCALL\n");
                break;
            case SSL_ERROR_SSL:
                printf("SSL_ERROR_SSL\n");
                break;
            default:
                printf("SOME other SSL error\n");
                break;
        }

        if (err != SSL_ERROR_SSL) {

            if (ERR_get_error() == 0) {
                perror("SSL_do_handshake ");
                printf("OpenSSL Error Queue is empty. Ret = %d\n", ret);
            } else {
                ERR_print_errors_fp(stderr);
            }
#if 0
            printf("==========================================================\n");
            printf("SSL ERROR: %s\n", ERR_error_string(err, NULL));
            printf("           %s\n", ERR_lib_error_string(err));
            printf("           %s\n", ERR_func_error_string(err));
            printf("           %s\n", ERR_reason_error_string(err));
            printf("==========================================================\n");
#endif
        }
    }

    dtls_srtp_send_any_pending_data(s);

    s->state = DTLS_SRTP_HANDSHAKING;

    return MB_OK;
}



mb_status_t dtls_srtp_session_inject_data(handle h_dtls, 
                    uint8_t *data, int len, int *is_handshake_done) {

    int written;
    X509 *peer_cert;
    dtls_srtp_session_t *s = (dtls_srtp_session_t *)h_dtls;

    *is_handshake_done = 0;

    fprintf(stderr, "received dtls data from remote of len [%d]\n", len);

    written = BIO_write(s->src_bio, data, len);
    if (written) {
        if (s->state == DTLS_SRTP_HANDSHAKING) {
            if (!SSL_is_init_finished(s->ssl)) {

                printf("&&&&&&&&&&&&&& SSL handshake NOT yet complete &&&&&&&&&&&&&&&&&&&\n");
                SSL_do_handshake(s->ssl); /* TODO; check return value? */
            }

            /*
             * Damn! The reason why the SSL was not returning as complete
             * was because we need to check the status even after every
             * call to SSL_do_handshake(). Costed me 2-3 days!
             */
            if (SSL_is_init_finished(s->ssl)) {

                EVP_MD *tmp_d;
                unsigned int i;

                printf("********** HANDSHAKE DONE **************\n");

                /* check the peer certificate */
                peer_cert = SSL_get_peer_certificate(s->ssl);
                if (peer_cert == NULL) {
                    fprintf(stderr, "DTLS Handshake "\
                            "completed. Peer certificate missing\n");
                    return MB_INVALID_PARAMS;
                }

                if (s->digest_type == DTLS_SHA1) {
                    tmp_d = EVP_sha1();
                    fprintf(stderr, "[DTLS]: Peer Digest type: SHA1\n");
                } else if (s->digest_type == DTLS_SHA256) {
                    tmp_d = EVP_sha256();
                    fprintf(stderr, "[DTLS]: Peer Digest type: SHA256\n");
                } else {
                    fprintf(stderr, "[DTLS]: Unsupported Digest type\n");
                    return MB_NOT_SUPPORTED;
                }

                X509_digest(peer_cert, tmp_d, s->peer_fp, &s->peer_fp_len);

                printf("PEER CERTIFICATE [Len=%d] FINGERPRINT: ", s->peer_fp_len);

                for (i = 0; i < s->peer_fp_len; i++) {
                    printf("%02X:", s->peer_fp[i]);
                }
                printf("\n");

                s->state = DTLS_SRTP_READY;
                *is_handshake_done = 1;
            }
        } else {
            /* TODO; we are ready, so these must be higher application data */
            int bytes;
            char *appdata = (char *) calloc(1, 1500);
            if (appdata == NULL) {
                fprintf(stderr, "Memory allocation failed\n");
                return MB_MEM_ERROR;
            }

            bytes = SSL_read(s->ssl, appdata, 1500);

            //fprintf(stderr, "Incoming => Number of bytes of Application data: %d\n", bytes);

            /* pass to the application for further processing */
            g_dtls_srtp.app_cb(s, appdata, bytes, s->app_handle);

            /* Freeing of appdata memory is application responsibility */
        }
    } else {
        printf("BIO_write() returned error\n");
    }

    dtls_srtp_send_any_pending_data(s);

    return MB_OK;
}



mb_status_t dtls_srtp_session_get_peer_fingerprint(
                    handle h_dtls, unsigned char *fp, uint32_t *fp_len) {

    dtls_srtp_session_t *s = (dtls_srtp_session_t *)h_dtls;

    if (s->state != DTLS_SRTP_READY) return MB_NOT_FOUND;

    if (*fp_len < s->peer_fp_len) return MB_MEM_INSUF;

    fprintf(stderr, "[DTLS]: Peer FP Len %d\n", s->peer_fp_len);

    /* TODO; use memcpy? */
    //strncpy((char *)fp, (char *)s->peer_fp, s->peer_fp_len);
    memcpy(fp, s->peer_fp, s->peer_fp_len);
    *fp_len = s->peer_fp_len;

    return MB_OK;
}



mb_status_t dtls_srtp_session_get_keying_material(
                        handle h_dtls, unsigned char *keying_material) {

    int ret;
    dtls_srtp_session_t *s = (dtls_srtp_session_t *)h_dtls;

    if (s->state != DTLS_SRTP_READY) return MB_NOT_FOUND;

    /* TODO; Need to ensure buf is atleast of required length */

    /* extract the keying material from the dtls association - rfc 5705 */
    ret = SSL_export_keying_material(s->ssl, keying_material, 
            (SRTP_MASTER_KEY_LEN * 2), "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0);
    if (ret != 1) {

        fprintf(stderr, "Error while "\
                "extracting the keying material from DTLS association\n");
        return MB_VALIDATON_FAIL;
    }

    return MB_OK;
}



mb_status_t dtls_srtp_inject_timer_event(handle timer_id, handle arg) {

    int sent;
    dtls_srtp_session_t *s = (dtls_srtp_session_t *)arg;

    if (s->timer_id != timer_id) {
        fprintf(stderr, "[DTLS} Stuck with Paranoid check!. Expired "\
                "timer id %p and dtls session timer id %p\n", 
                timer_id, s->timer_id);
        return MB_INVALID_PARAMS;
    }

    /* 
     * in case the session is in ready state, then sit pretty. We need 
     * re-transmission only for handshaking messages so that it is completed.
     * For application data, we expect application protocol to handle the
     * re-transmissions.
     */
    if (s->state == DTLS_SRTP_READY) {
        fprintf(stderr, "The DTLS session has moved to READY state, hence "\
                "ignoring any further retransmission. And ignoring current "\
                "timer expiry event with handle %p\n", timer_id);
        return MB_OK;
    }

    /* resend the last sent message and restart timer */
    sent = g_dtls_srtp.cb(s, s->sent_msg, s->sent_msg_len, s->app_handle);

    if (sent < s->sent_msg_len) {
        fprintf(stderr, "Error Re-transmitting DTLS data. Sent only "\
                "%d bytes against given %d bytes\n", sent, s->sent_msg_len);
        /* TODO; what do we do now? error? */
    }

    s->timer_id = g_dtls_srtp.timer_start_cb(DTLS_RETX_TIMER_VAL, s);
    if (s->timer_id) {
        fprintf(stderr, "Started DTLS retransmission "\
                "timer for %d duration\n", DTLS_RETX_TIMER_VAL);
    } else {
        fprintf(stderr, "Starting DTLS retransmission "\
                    "timer for %d duration FAILED\n", DTLS_RETX_TIMER_VAL);
    }

    return MB_OK;
}



mb_status_t dtls_srtp_destroy_session(handle h_dtls) {

    return MB_OK;
}



mb_status_t dtls_srtp_deinit(void) {

    return MB_OK;
}



mb_status_t dtls_srtp_session_send_app_data(
                handle h_dtls, uint8_t *data, int len) {

    int ret;
    dtls_srtp_session_t *s = (dtls_srtp_session_t *)h_dtls;

    if (s->state != DTLS_SRTP_READY) return MB_NOT_FOUND;

    ret = SSL_write(s->ssl, data, len);
    if (ret <= 0) {
        int what = SSL_get_error(s->ssl, ret);
        printf("[%d] SSL_write: %d\n", ret, what);
        switch(what) {
            case SSL_ERROR_NONE:
                printf("SSL_ERROR_NONE\n");
                break;
            case SSL_ERROR_ZERO_RETURN:
                printf("SSL_ERROR_ZERO_RETURN\n");
                break;
            case SSL_ERROR_WANT_READ:
                printf("SSL_ERROR_WANT_READ\n");
                break;
            case SSL_ERROR_WANT_WRITE:
                printf("SSL_ERROR_WANT_WRITE\n");
                break;
            case SSL_ERROR_WANT_CONNECT:
                printf("SSL_ERROR_WANT_CONNECT\n");
                break;
            case SSL_ERROR_WANT_ACCEPT:
                printf("SSL_ERROR_WANT_ACCEPT\n");
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                printf("SSL_ERROR_WANT_X509_LOOKUP\n");
                break;
            case SSL_ERROR_SYSCALL:
                printf("SSL_ERROR_SYSCALL\n");
                break;
            case SSL_ERROR_SSL:
                printf("SSL_ERROR_SSL\n");
                break;
            default:
                printf("SOME other SSL error\n");
                break;
        }

        fprintf(stderr, "SSL_write() error\n");

        return MB_INT_ERROR;
    } else {

        //fprintf(stderr, "Wrote [%d] bytes of app data to dtls session\n", ret);
    }

    dtls_srtp_send_any_pending_data(s);

    return MB_OK;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

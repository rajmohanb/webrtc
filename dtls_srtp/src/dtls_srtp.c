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



void dtls_srtp_send_data(dtls_srtp_session_t *s) {

    int bytes = BIO_ctrl_pending(s->sink_bio);

    printf("SSL SINK BIO PENDING BYTES: %d\n", bytes);
}



mb_status_t dtls_srtp_init(void) {

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



mb_status_t dtls_srtp_create_session(
                dtls_setup_role_type_t role, int sock, handle *h_dtls) {

    dtls_srtp_session_t *s;

    /* allocate memory for the new session */
    s = (dtls_srtp_session_t *) calloc(1, sizeof(dtls_srtp_session_t));
    if (s == NULL) {
        fprintf(stderr, "Memory allocation for new DTLS_SRTP session failed\n");
        return MB_MEM_ERROR;
    }

    printf("Stage 1\n");

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

    printf("Stage 2\n");

    /* setup the source/read and sink/write bio */
#if 0
    s->src_bio = BIO_new(BIO_s_mem());
    if (s->src_bio == NULL) {
        fprintf(stderr, "Creation of source BIO for session failed\n");
        return MB_INT_ERROR;
    }
    BIO_set_mem_eof_return(s->src_bio, -1);

    s->sink_bio = BIO_new(BIO_s_mem());
    if (s->sink_bio == NULL) {
        fprintf(stderr, "Creation of source BIO for session failed\n");
        return MB_INT_ERROR;
    }
    BIO_set_mem_eof_return(s->sink_bio, -1);
#else
    s->src_bio = BIO_new_socket(sock, 1);
    if (s->src_bio == NULL) {
        fprintf(stderr, "Creation of source BIO for session failed\n");
        return MB_INT_ERROR;
    }

    printf("Stage 3\n");

    s->sink_bio = BIO_new_socket(sock, 1);
    if (s->sink_bio == NULL) {
        fprintf(stderr, "Creation of source BIO for session failed\n");
        return MB_INT_ERROR;
    }
#endif

    printf("Stage 4\n");

    SSL_set_bio(s->ssl, s->src_bio, s->sink_bio);

    s->role = role;
    if (role == DTLS_ACTIVE) {
        SSL_set_connect_state(s->ssl);
        printf("SSL session role: Connect role\n");
    } else if (role == DTLS_PASSIVE) {
        SSL_set_accept_state(s->ssl);
        printf("SSL session role: Accept role\n");
    }

    printf("Stage 5\n");

    *h_dtls = s;

    return MB_OK;

    /* TODO; handle error scenarios and cleanup */
}



mb_status_t dtls_srtp_session_do_handshake(handle h_dtls) {

    int ret;
    dtls_srtp_session_t *s = (dtls_srtp_session_t *)h_dtls;

    ret = SSL_do_handshake(s->ssl);
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

    return MB_OK;
}



mb_status_t dtls_srtp_destroy_session(handle h_dtls) {

    return MB_OK;
}



mb_status_t dtls_srtp_deinit(void) {

    return MB_OK;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

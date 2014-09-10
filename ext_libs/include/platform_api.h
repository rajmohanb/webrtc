/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
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

#ifndef PLATFORM_API__H
#define PLATFORM_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/md5.h>

#define PLATFORM_TIMER_PERIODIC_TIME_VALUE  20 /** milliseconds */

#define IP_ADDR_MAX_LEN                     46

#define DEV_RANDOM_FILE                     "/dev/urandom"

#define PLATFORM_TIMER_MMAP_FILE_PATH       "/timertable"

typedef struct
{
    char      src_ip_addr[IP_ADDR_MAX_LEN];
    int       src_port;

    char      dest_ip_addr[IP_ADDR_MAX_LEN];
    int       dest_port;

} struct_pkt_src_dest;

typedef void (*timer_expiry_callback) (void *timer_id, void *arg);

bool platform_init(void);

void platform_exit(void);

void *platform_malloc(unsigned int size);

void *platform_calloc(unsigned int nmemb, unsigned int size);

void *platform_memset(void *s, int c, size_t n);

void *platform_memcpy(void *dest, void *src, unsigned int n);

int platform_memcmp(void *s1, void *s2, unsigned int n);

void platform_free(void *obj);

void *platform_start_timer(int duration, 
                                timer_expiry_callback timer_cb, void *arg);

bool platform_stop_timer(void *timer_id);

unsigned int platform_create_socket(int domain, int type, int protocol);

unsigned int platform_bind_socket(int sockfd, struct sockaddr *addr, int addrlen);

unsigned int platform_socket_send(int sock_fd, 
        unsigned char *buf, unsigned int len, int flags);

unsigned int platform_socket_sendto(int socket, 
        unsigned char *buf, unsigned int len, int flags, int family, 
        unsigned int dest_port, char *dest_ipaddr);

unsigned int platform_socket_recv(int sock_fd, 
        unsigned char *buf, unsigned int buf_size, int flags);

unsigned int platform_socket_recvfrom(int sock_fd, unsigned char *buf, 
        unsigned int buf_size, int flags, unsigned char *src_ipaddr, 
        unsigned int *src_port);

unsigned int platform_socket_listen(
        int *sockfd_list, int num_fd, int *sockfd_act_list);

bool platform_get_random_data(unsigned char *data, unsigned int len);

unsigned long long int platform_64bit_random_number(void);

void platform_hmac_sha
(
  char*    k,     /* secret key */
  int      lk,    /* length of the key in bytes */
  char*    d,     /* data */
  int      ld,    /* length of data in bytes */
  char*    out,   /* output buffer, at least "t" bytes */
  int      t
);

uint32_t platform_crc32(uint8_t *data, size_t len);

#if 0
void platform_log(char *file_name, 
        int line_num, enum_stun_log_level level, char *format, ...);
#endif


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

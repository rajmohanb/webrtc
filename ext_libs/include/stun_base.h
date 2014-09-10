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

#ifndef STUN_BASE__H
#define STUN_BASE__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include "platform_api.h"


#ifdef WINDOWS

typedef     unsigned short  u_int16;
typedef     signed short    s_int16;
typedef     unsigned int    u_int32;
typedef     signed int      s_int32;
typedef     unsigned long long u_int64;
typedef     signed long long s_int64;
typedef     unsigned char   u_char;
typedef     signed char     s_char;
typedef     unsigned char   u_int8;
typedef     char            s_int8;

#endif


typedef     uint8_t         u_char;
typedef     char            s_char;

typedef     bool            bool_t;
typedef     void*           handle;

#define NE !=
#define LT <
#define GT >
#define LE <=
#define GE >=
#define EQ ==
#define AND &&
#define OR ||

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE
#endif


#ifndef NULL
#define     NULL            0x00
#endif

#define STUN_OK                 0
#define STUN_INT_ERROR          1
#define STUN_MEM_ERROR          2
#define STUN_INVALID_PARAMS     3
#define STUN_NOT_FOUND          4
#define STUN_TERMINATED         5
#define STUN_ENCODE_FAILED      6
#define STUN_DECODE_FAILED      7
#define STUN_MEM_INSUF          8
#define STUN_NOT_SUPPORTED      9
#define STUN_TRANSPORT_FAIL     10
#define STUN_VALIDATON_FAIL     11
#define STUN_NO_RESOURCE        12
#define STUN_MSG_NOT            13
#define STUN_BINDING_DONE       14
#define STUN_BINDING_CHANGED    15


#define stun_malloc platform_malloc
#define stun_calloc platform_calloc
#define stun_free(x) { if(x) platform_free(x); x = NULL; }
#define stun_memset platform_memset
#define stun_memcpy platform_memcpy
#define stun_memcmp platform_memcmp
#define stun_MD5_CTX MD5_CTX
#define stun_MD5_Init MD5_Init
#define stun_MD5_Update MD5_Update
#define stun_MD5_Final MD5_Final
#define platform_md5 MD5
#define platform_hmac_sha platform_hmac_sha
#define stun_strcpy strcpy
#define stun_strncpy strncpy
#define stun_snprintf snprintf
#define stun_sprintf sprintf
#define stun_strcmp strcmp
#define stun_strncmp strncmp
#define stun_strlen strlen
#define platform_time time
#define platform_rand rand
#define platform_srand srand


#define ICE_IP_ADDR_MAX_LEN     46


typedef enum
{
    LOG_SEV_EMERG = 0,
    LOG_SEV_ALERT,
    LOG_SEV_CRITICAL,
    LOG_SEV_ERROR,
    LOG_SEV_WARNING,
    LOG_SEV_NOTICE,
    LOG_SEV_INFO,
    LOG_SEV_DEBUG,
    LOG_SEV_MAX,
} stun_log_level_t;


typedef enum
{
    STUN_INET_ADDR_IPV4,
    STUN_INET_ADDR_IPV6,
    STUN_INET_ADDR_MAX,
} stun_inet_addr_type_t;


typedef enum {
    ICE_TRANSPORT_UDP = 0,
    ICE_TRANSPORT_TCP,
    ICE_TRANSPORT_INVALID,
} stun_transport_protocol_type_t;


typedef struct 
{
    stun_inet_addr_type_t   host_type;
    u_char                  ip_addr[ICE_IP_ADDR_MAX_LEN];
    uint32_t                port;
} stun_inet_addr_t;


/** use __TIME__ !!! */
#define ICE_LOG(level, ...) app_log(level, __FILE__, __LINE__, ##__VA_ARGS__)

void app_log(stun_log_level_t level,
        char *file_name, uint32_t line_num, char *format, ...);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

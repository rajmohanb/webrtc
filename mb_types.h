/*******************************************************************************
*                                                                              *
*                 Copyright (C) 2014, MindBricks Technologies                  *
*                  Rajmohan Banavi (rajmohanbanavi@gmail.com)                  *
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

#ifndef MB_BASE__H
#define MB_BASE__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#ifndef TRUE
#define TRUE 1
#endif


#ifndef FALSE
#define FALSE
#endif


typedef  void*   handle;


typedef enum {
    MB_OK = 1,
    MB_INT_ERROR = 2,
    MB_MEM_ERROR = 3,
    MB_INVALID_PARAMS = 4,
    MB_NOT_FOUND = 5,
    MB_TERMINATED = 6,
    MB_ENCODE_FAILED = 7,
    MB_DECODE_FAILED = 8,
    MB_MEM_INSUF = 9,
    MB_NOT_SUPPORTED = 10,
    MB_TRANSPORT_FAIL = 11,
    MB_VALIDATON_FAIL = 12,
    MB_NO_RESOURCE = 13,
    MB_MSG_NOT = 14,
} mb_status_t;


typedef enum
{
    MBLOG_EMERG = 0,
    MBLOG_ALERT,
    MBLOG_CRITICAL,
    MBLOG_ERROR,
    MBLOG_WARNING,
    MBLOG_NOTICE,
    MBLOG_INFO,
    MBLOG_DEBUG,
    MBLOG_MAX,
} mb_log_level_t;


typedef enum
{
    MB_INET_ADDR_IPV4,
    MB_INET_ADDR_IPV6,
    MB_INET_ADDR_MAX,
} mb_inet_addr_type_t;


typedef enum {
    MB_TRANSPORT_UDP = 0,
    MB_TRANSPORT_TCP,
    MB_TRANSPORT_INVALID,
} mb_transport_protocol_type_t;


#define MB_IPADDR_MAX_LEN   46

typedef struct 
{
    mb_inet_addr_type_t   host_type;
    uint8_t               ip_addr[MB_IPADDR_MAX_LEN];
    uint32_t              port;
} mb_inet_addr_t;


/** use __TIME__ !!! */
#ifndef MB_LOG
#define MB_LOG(level, ...) app_log(level, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

void mb_log(mb_log_level_t level,
        char *file_name, uint32_t line_num, char *format, ...);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

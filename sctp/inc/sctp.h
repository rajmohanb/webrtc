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

#ifndef SCTP__H
#define SCTP__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


typedef int (*dc_sctp_send_data_cb) (
            handle sctp, char *buf, int len, handle app_handle);


mb_status_t dc_sctp_init(dc_sctp_send_data_cb);


mb_status_t dc_sctp_create_association(uint16_t local_port, 
                                   uint16_t peer_port, uint16_t is_dtls_client, 
                                   handle app_handle, handle *sctp);


mb_status_t dc_sctp_association_inject_received_msg(
                                        handle sctp, void *data, uint32_t len);


mb_status_t dc_sctp_destroy_association(handle sctp);


mb_status_t dc_sctp_deinit(void);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

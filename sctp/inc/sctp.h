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


mb_status_t dc_sctp_init(void);


mb_status_t dc_sctp_create_association(
                uint16_t local_port, uint16_t peer_port, handle *sctp);


mb_status_t dc_sctp_destroy_association(handle sctp);


mb_status_t dc_sctp_deinit(void);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/

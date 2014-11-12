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

#include <usrsctp.h>

#include <mb_types.h>



mb_status_t sctp_init(void) {

    usrsctp_init(0, NULL, NULL);

    return MB_OK;
}



mb_status_t sctp_deinit(void) {

    if (usrsctp_finish() != 0) {
        fprintf(stderr, "usrsctp_finish returned error\n");
        return MB_INT_ERROR;
    }

    return MB_OK;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

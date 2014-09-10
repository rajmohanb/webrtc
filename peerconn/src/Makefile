#*******************************************************************************
#                                                                              #
#                 Copyright (C) 2014, MindBricks Technologies                  #
#                  Rajmohan Banavi (rajmohan@mindbricks.com)                   #
#                     MindBricks Confidential Proprietary.                     #
#                            All Rights Reserved.                              #
#                                                                              #
#*******************************************************************************
#                                                                              #
# This document contains information that is confidential and proprietary to   #
# MindBricks Technologies. No part of this document may be reproduced in any   #
# form whatsoever without prior written approval from MindBricks Technologies. #
#                                                                              #
#******************************************************************************/

EXT_DEPS := /home/rajmohan/MindBricks/webrtc_stack/ext_libs

LIB := libpc.a

SRC = pc.c pc_fsm.c pc_utils.c

INCLUDE := -I. -I../../ -I../inc -I$(EXT_DEPS)/include -I../../dtls_srtp/inc

CFLAGS += -c -g -Wall -Wstrict-prototypes $(INCLUDE)

OBJS:=$(SRC:c=o)

.c.o :
	@echo "[CC] " $< ...
	$(CC) $(CFLAGS) -o $*.o $<

archive:$(OBJS)
	@echo "Building library" $(LIB)
	@$(AR) $(ARFLAGS) $(LIB) $(OBJS) 

clean:
	@echo "Cleaning library" $(LIB)
	@rm -rf $(LIB) *.o

#*******************************************************************************
#                                                                              #
#               Copyright (C) 2009-2014, MindBricks Technologies               #
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

MB_WEBRTC_APP := rtc_sig
TARGET := all
SRC := main.c rtcsig_fsm.c

# Include header file path
INCLUDE := -I. -I../ -I../peerconn/inc -I../ext_libs/include

MB_WEBRTC_LIBS := ../ext_libs/libs/libwebsockets.a \
	-ljansson -lz -lssl -lcrypto -lm -lrt -ldl

CFLAGS += -g -Wall -Wstrict-prototypes -c $(INCLUDE) -DLINUX

OBJ:=$(SRC:c=o)

.c.o :
	@echo [CC] 	$< ...
	$(CC) $(CFLAGS) -o $*.o $<

$(TARGET) : clean $(MB_WEBRTC_APP)

$(MB_WEBRTC_APP): $(OBJ)
	@echo "Creating webrtc application sample... " $(MB_WEBRTC_APP) 
	$(CC) $(OBJ) -o $(MB_WEBRTC_APP) $(MB_WEBRTC_LIBS)

clean:
	@echo "Removing all sample ... "
	rm -rf $(MB_WEBRTC_APP) $(OBJ)


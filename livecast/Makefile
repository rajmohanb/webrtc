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

MB_WEBRTC_APP := livecast
TARGET := all
SRC := livecast.c channel.c utils.c

# Include header file path
INCLUDE := -I. -I../ -I../peerconn/inc -I../ext_libs/include

MB_WEBRTC_LIBS := ../peerconn/src/libpc.a ../ext_libs/libs/libsdp.a \
	../ext_libs/libs/libsu.a ../ext_libs/libs/lib_trickleice.a \
	../dtls_srtp/src/libdtls_srtp.a ../rtcp/src/librtcp.a \
	../ext_libs/libs/lib_turn.a ../ext_libs/libs/lib_ice_conncheck.a \
	../ext_libs/libs/lib_stun_txn.a ../ext_libs/libs/lib_stun_encdec.a \
	../ext_libs/libs/lib_stun_msg.a ../ext_libs/libs/lib_stun_binding.a \
	../ext_libs/libs/lib_platform.a ../ext_libs/libs/libsrtp.a \
	-lssl -lcrypto -ljansson -lm -lrt -ldl -lpthread

CFLAGS += -g -Wall -Wstrict-prototypes -c $(INCLUDE) -DLINUX #-fsanitize=address -fno-omit-frame-pointer

LFLAGS = #-fsanitize=address -fno-omit-frame-pointer

OBJ:=$(SRC:c=o)

.c.o :
	@echo [CC] 	$< ...
	$(CC) $(CFLAGS) -o $*.o $<

$(TARGET) : clean $(MB_WEBRTC_APP)

$(MB_WEBRTC_APP): $(OBJ)
	@echo "Creating webrtc application sample... " $(MB_WEBRTC_APP) 
	$(CC) $(LFLAGS) $(OBJ) -o $(MB_WEBRTC_APP) $(MB_WEBRTC_LIBS)

clean:
	@echo "Removing all sample ... "
	rm -rf $(MB_WEBRTC_APP) $(OBJ)


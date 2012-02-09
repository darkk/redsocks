####################################
# Build libevent as separate library

LOCAL_PATH := $(call my-dir)
JNI_PATH := $(LOCAL_PATH)
REDSOCKS_PATH := $(LOCAL_PATH)/../..
LOCAL_PATH := $(REDSOCKS_PATH)

include $(CLEAR_VARS)

LOCAL_MODULE:= redsocks

LOCAL_SRC_FILES := \
	parser.c \
	main.c \
	redsocks.c \
	log.c \
	http-connect.c \
	socks4.c \
	socks5.c \
	http-relay.c \
	base.c \
	base64.c \
	md5.c \
	http-auth.c \
	utils.c \
	redudp.c \
	dnstc.c \
	android/version.c

LOCAL_C_INCLUDES := \
	$(JNI_PATH)/libevent \
	$(JNI_PATH)/libevent/android

LOCAL_STATIC_LIBRARIES := libevent

LOCAL_CFLAGS := -O2 -std=gnu99 -Wall -DUSE_IPTABLES

include $(BUILD_EXECUTABLE)

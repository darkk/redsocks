####################################
# Build libevent as separate library

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE:= libevent

LOCAL_SRC_FILES := \
	libevent/evbuffer.c \
	libevent/buffer.c \
    libevent/event.c \
    libevent/evutil.c \
    libevent/epoll.c \
    libevent/log.c \
    libevent/poll.c \
    libevent/select.c \
    libevent/signal.c

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/libevent \
	$(LOCAL_PATH)/libevent/android

LOCAL_CFLAGS := -DHAVE_CONFIG_H -DANDROID -fvisibility=hidden

include $(BUILD_STATIC_LIBRARY)

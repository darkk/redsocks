LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

include $(LOCAL_PATH)/libevent.mk

include $(LOCAL_PATH)/redsocks.mk

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES :=

ifeq ($(strip $(INTEL_FEATURE_ARKHAM)),true)
LOCAL_SRC_FILES += enabled/com/intel/config/FeatureConfig.java
else
LOCAL_SRC_FILES += disabled/com/intel/config/FeatureConfig.java
endif
LOCAL_MODULE := com.intel.config
LOCAL_MODULE_TAGS := optional
include $(BUILD_JAVA_LIBRARY)


# install the com.intel.config.xml file into /system/etc/permissions/
include $(CLEAR_VARS)
LOCAL_MODULE := com.intel.config.xml
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/permissions
LOCAL_SRC_FILES := $(LOCAL_MODULE)
include $(BUILD_PREBUILT)

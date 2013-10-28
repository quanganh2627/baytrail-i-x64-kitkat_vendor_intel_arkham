ifeq ($(strip $(INTEL_FEATURE_ARKHAM)),true)

LOCAL_PATH := $(call my-dir)

arkham.core_src_files := $(call all-java-files-under, enabled/base/core/java)
arkham.core_java_libraries := core
arkham.stubs_src_files := $(TARGET_OUT_COMMON_INTERMEDIATES)/JAVA_LIBRARIES/arkham-jar_intermediates/src
arkham_internal_api_file := $(TARGET_OUT_COMMON_INTERMEDIATES)/PACKAGING/arkham-api.txt


# Generate the stub source files
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(arkham.core_src_files)
LOCAL_JAVA_LIBRARIES := $(arkham.core_java_libraries)
LOCAL_MODULE_CLASS := JAVA_LIBRARIES
LOCAL_DROIDDOC_SOURCE_PATH := $(LOCAL_PATH)/enabled/base/core/java
LOCAL_DROIDDOC_HTML_DIR :=
LOCAL_DROIDDOC_OPTIONS:= \
    -stubs $(arkham.stubs_src_files) \
    -stubpackages com.intel.arkham \
    -api $(arkham_internal_api_file)
LOCAL_DROIDDOC_CUSTOM_TEMPLATE_DIR := build/tools/droiddoc/templates-sdk
LOCAL_UNINSTALLABLE_MODULE := true
LOCAL_MODULE := arkham-stubs
LOCAL_MODULE_TAGS := optional
include $(BUILD_DROIDDOC)
arkham_stubs_stamp := $(full_target)
$(arkham_internal_api_file) : $(full_target)


# Build the stub source files into a jar.
include $(CLEAR_VARS)
LOCAL_MODULE := arkham-jar
LOCAL_MODULE_TAGS := optional
LOCAL_JAVA_LIBRARIES := $(arkham.core_java_libraries)
LOCAL_SOURCE_FILES_ALL_GENERATED := true
include $(BUILD_STATIC_JAVA_LIBRARY)
# Make sure to run droiddoc first to generate the stub source files.
$(full_classes_compiled_jar) : $(arkham_stubs_stamp)
arkham_stubs_jar := $(full_classes_jar)


#TODO: add API check (see frameworks/testing/uiautomator/library/)

endif
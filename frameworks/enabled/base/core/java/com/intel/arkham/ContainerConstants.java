/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.intel.arkham;

/**
 * Utility class containing constants used by containers
 */
public interface ContainerConstants {

    // Errors
    public static final int NO_ERROR                               = 0;
    public static final int ERROR_NO_SERVICE                       = -1;
    public static final int ERROR_PERMISSION_DENIED                = -2;
    public static final int ERROR_CONTAINER_DISABLED               = -3;
    public static final int ERROR_COULD_NOT_MOUNT                  = -4;
    public static final int ERROR_INVALID_MDM_PACKAGE              = -5;
    public static final int ERROR_MULTIPLE_CONTAINERS_UNSUPPORTED  = -6;
    public static final int ERROR_CONTAINER_NAME_INVALID           = -7;
    public static final int ERROR_USER_CREATION_FAILED             = -8;
    public static final int ERROR_DATABASE_NOT_UPDATED             = -9;
    public static final int ERROR_PASSWORD_CREATION_FAILED         = -10;
    public static final int ERROR_CONTAINER_LIMIT_REACHED          = -11;
    public static final int ERROR_COPY_FAILED                      = -12;
    public static final int ERROR_FILE_NOT_FOUND                   = -13;
    public static final int ERROR_INVALID_FILE_PATH                = -14;
    public static final int ERROR_INVALID_PACKAGE                  = -15;
    public static final int ERROR_APP_NOT_WHITELISTED              = -16;
    public static final int ERROR_INVALID_POLICY                   = -17;
    public static final int ERROR_SET_POLICY_FAILED                = -18;

    /**
     * Account type used for syncing container contacts outside the container if policy allows it
     */
    public static final String SYNC_ACCOUNT_TYPE = "com.intel.arkham.accounts";

    /**
     * For ARKHAM-669
     * Use with {@link #getSystemService} to retrieve a
     * {@link com.intel.arkham.ContainerManager} for doing container management.
     *
     * @see #getSystemService
     */
    public static final String CONTAINER_MANAGER_SERVICE = "container_manager";

    /**
     * For ARKHAM-242
     * Use with {@link #getSystemService} to retrieve a
     * {@link com.intel.arkham.ContainerPolicyManager} for working with
     * container policy management.
     *
     * @see #getSystemService
     */
    public static final String CONTAINER_POLICY_SERVICE = "container_policy";

    // ARKHAM-72 START
    /**
     * The GID range between FIRST_CONTAINER_GID and LAST_CONTAINER_GID
     * is reserved for container isolation enforcement operations.
     * @hide
     */
    public static final int FIRST_CONTAINER_GID = 3701;
    /**
     * @hide
     */
    public static final int LAST_CONTAINER_GID = 3704;
    // ARKHAM-72 END

    // Policies to be passed from MDM outside the container to MDM inside

    // DPM policies
    public static final String POLICY_CAMERA_DISABLED = "disableCamera";
    public static final String POLICY_KEYGUARD_DISABLED_FEATURES = "disabledKeyguardFeatures";
    public static final String POLICY_MAX_FAILED_PASSWORDS_FOR_WIPE
            = "maximumFailedPasswordsForWipe";
    public static final String POLICY_MAX_TIME_TO_LOCK = "maximumTimeToUnlock";
    public static final String POLICY_PASSWORD_EXPIRATION_TIMEOUT = "passwordExpirationTimeout";
    public static final String POLICY_PASSWORD_HISTORY_LENGTH = "passwordHistoryLength";
    public static final String POLICY_PASSWORD_MINIMUM_LENGTH = "minimumPasswordLength";
    public static final String POLICY_PASSWORD_MINIMUM_LETTERS = "minimumPasswordLetters";
    public static final String POLICY_PASSWORD_MINIMUM_LOWER_CASE = "minimumPasswordLowerCase";
    public static final String POLICY_PASSWORD_MINIMUM_NON_LETTER = "minimumPasswordNonLetter";
    public static final String POLICY_PASSWORD_MINIMUM_NUMERIC = "minimumPasswordNumeric";
    public static final String POLICY_PASSWORD_MINIMUM_SYMBOLS = "minimumPasswordSymbols";
    public static final String POLICY_PASSWORD_MINIMUM_UPPER_CASE = "minimumPasswordUpperCase";
    public static final String POLICY_PASSWORD_QUALITY = "passwordQuality";
    public static final String POLICY_STORAGE_ENCRYPTION = "encryptionRequested";
    // TODO: lockNow and resetPassword options to be given to MDM outside the container

    // CPM policies / Other policies
    public static final String POLICY_MAX_FAILED_PASSWORDS_FOR_DISABLE
            = "maximumFailedPasswordsForDisable";
    public static final String POLICY_ALLOW_COPY_FROM_CONTAINER = "exportClipboardContent";
    public static final String POLICY_ALLOW_COPY_INTO_CONTAINER = "importClipboardContent";
    public static final String POLICY_MERGE_CONTACTS_PROVIDER = "mergeContactsProvider";
    public static final String POLICY_EXPORT_CALENDAR = "exportCalendar";
    public static final String POLICY_EXPORT_EMAIL = "exportEmail";
    public static final String POLICY_CONTAINER_LOCK_TIMEOUT = "containerLockTimeout";
    public static final String POLICY_CONTAINER_LOCK_TIMEOUT_TYPE = "containerLockTimeoutType";
    public static final String POLICY_APP_WHITE_LIST = "applicationWhiteList";
    public static final String POLICY_SYSTEM_BLACK_LIST = "systemBlackList";
    public static final String POLICY_CONTACT_FIELD_WHITE_LIST = "contactFieldWhiteList";

    public static final int NOTIFICATION_ID_CONTAINER_LOCKED = 1001;

    // Permissions
    public static final int PERMISSION_CONTACTS_PROVIDER = 0x00000001;
    public static final int PERMISSION_LAUNCHER          = 0x00000010;
    public static final int PERMISSION_ADMIN             = 0x00000100;
    public static final int PERMISSION_CONTAINER_ADMIN   = 0x00001000;
    public static final int PERMISSION_SYSTEM            = 0x00010000;
    public static final int PRIMARY_USER = 0;
    public static final String ERROR_ADMIN_PERMISSION_REQUIRED = "Admin privilege required";
    public static final String ERROR_CONTAINER_ADMIN_PERMISSION_REQUIRED
            = "Container admin privilege required";
    public static final String ERROR_LAUNCHER_PERMISSION_REQUIRED = "Launcher privilege required";
    public static final String ERROR_CONTACTS_PROVIDER_PERMISSION_REQUIRED
            = "Contacts Provider privilege required";
    public static final String ERROR_SYSTEM_PERMISSION_REQUIRED
            = "Root or system privilege required";

    // Misc
    public static final String ACTION_SET_POLICY = "com.intel.arkham.SET_POLICY";
    public static final String ACTION_POLICY_RESULT = "com.intel.arkham.POLICY_RESULT";
    public static final String ACTION_INSTALL_APP = "com.intel.arkham.INSTALL_APP";
    public static final String ACTION_REMOVE_APP = "com.intel.arkham.REMOVE_APP";
    public static final String ACTION_CONTAINER_REMOVED = "com.intel.arkham.CONTAINER_REMOVED";
    public static final String EXTRA_CONTAINER_MDM_BROADCAST = "containerMdmBroadcast";
    public static final String EXTRA_CONTAINER_ID = "containerId";
    public static final String EXTRA_POLICY_BUNDLE = "policyBundle";
    public static final String EXTRA_POLICY_RESULT_BUNDLE = "policyResultBundle";
    public static final String EXTRA_APK_FILE_PATH = "apkFilePath";
    public static final String EXTRA_PACKAGE_NAME = "packageName";
    public static final String EXTRA_BACKGROUND_IMAGE_PATH = "backgroundImagePath";

    // Password expiry related extras
    public static final String EXTRA_PASSWORD_EXPIRY_FLAG = "password_expiry_flag";
    public static final String EXTRA_PASSWORD_EXPIRY_DAYS_REMAINING
            = "password_expiry_days_remaining";

    /**
     * This broadcast intent will be sent after an application is installed, removed,
     * enabled or disabled. It is directed at container launcher applications.
     */
    public static final String ACTION_REFRESH_CONTAINER = "com.intel.arkham.REFRESH_CONTAINER";

    /**
     * This broadcast is sent instead of USER_STARTING. Used at Sync Manager.
     */
    public static final String ACTION_CONTAINER_OPENED = "com.intel.arkham.CONTAINER_OPENED";

    /**
     * This broadcast is sent to the MDM when container creation is complete
     */
    public static final String ACTION_CONTAINER_CREATED = "com.intel.arkham.CONTAINER_CREATED";

    /**
     * This broadcast is sent to the container launcher to update its background
     */
    public static final String ACTION_UPDATE_LAUNCHER_BACKGROUND = "com.intel.arkham.UPDATE_LAUNCHER_BACKGROUND";

    /**
     * Default MDM inside the container. This should be disabled for container owners.
     */
    public static final String PACKAGE_DEFAULT_CONTAINER_MDM = "com.intel.arkham.containermdm";

    public static final String GMS_APPS_PACKAGE_PREFIX = "com.google.android";

    public static final String ACCOUNT_TYPE_CONTAINER = "account_type_container";

    /**
     * Broadcast sent by Package Manager whenever an app other than
     * MDM inside the container enables another app inside the container.
     */
    public static final String ACTION_APP_ENABLED = "com.intel.arkham.APP_ENABLED";
    public static final String EXTRA_PACKAGE_INFO = "com.intel.arkham.PACKAGE_INFO";

    public static final String EXTRA_CONTAINER_INFO = "containerInfo";

    public static final String ACTION_UNLOCK_CONTAINER_KEYSTORE = "com.intel.arkham.ACTION_UNLOCK_CONTAINER_KEYSTORE";
    public static final String EXTRA_KEYSTORE_PASSWORD = "keystore_password";

    public static final String ContainerPackageRegexp = "(_container_)([0-9]+)$";
}

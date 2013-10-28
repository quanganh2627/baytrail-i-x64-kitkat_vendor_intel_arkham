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

package com.android.server;

import android.app.Activity;
import android.app.ActivityManagerNative;
import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.UserInfo;
import android.os.AsyncTask;
import android.os.Binder;
import android.os.Environment;
import android.os.Handler;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.os.UserManager;

import android.provider.Settings;
import android.util.Log;
import android.util.Slog;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Date;
import java.util.Set;

import com.intel.arkham.IContainerManager;
import com.intel.arkham.ContainerManager;
import com.intel.arkham.ContainerConstants;

/**
 * Implementation of the device policy APIs.
 */
/** {@hide} */

public class ExtendDevicePolicyManagerService extends DevicePolicyManagerService {
    private static final String TAG = "ExtendDevicePolicyManagerService";

    private UserManager mUserManager;
    private Context mContext;

    public ExtendDevicePolicyManagerService(Context context) {
        super(context);
        mContext = context;
        mUserManager = (UserManager) mContext.getSystemService(Context.USER_SERVICE);
    }

    void sendAdminCommandLocked(ActiveAdmin admin, String action, BroadcastReceiver result) {
        Slog.d(TAG, "sendAdminCommandLocked");
        Intent intent = new Intent(action);
        intent.setComponent(admin.info.getComponent());
        if (action.equals(DeviceAdminReceiver.ACTION_PASSWORD_EXPIRING)) {
            intent.putExtra("expiration", admin.passwordExpirationDate);
        }
        if (result != null) {
            mContext.sendOrderedBroadcastAsUser(intent, admin.getUserHandle(),
                    null, result, mHandler, Activity.RESULT_OK, null, null);
        } else {
            /*
             * ARKHAM - 174 Report successful and failed attempts for container users
             * Instead of sending the intents to the primary user, send them to the
             * actual container user.
             */
            UserHandle user = UserHandle.OWNER;
            UserInfo info = mUserManager.getUserInfo(admin.getUserHandle().getIdentifier());
            if (info != null && info.isContainer()) {
                user = admin.getUserHandle();
            }
            mContext.sendBroadcastAsUser(intent, user);
            // ARKHAM - Changes End.
        }
    }

    /* ARKHAM-789 Enable container device admin after opening the container. */
    public void reportSuccessfulPasswordAttempt(int userHandle) {
        UserInfo user = mUserManager.getUserInfo(userHandle);
        if (user != null && user.isContainer()) {
            /* Force the DPM to reload container policy info.
             * This is needed to activate the internal MDM after the container
             * file system has been decrypted. */
            mUserData.put(userHandle, null);
        }
        super.reportSuccessfulPasswordAttempt(userHandle);
    }

    /* Check to see if the policy xml exists or if it's encrypted. Only attempt to
     * write to it when it's unencrypted and the container is open. */
    protected void saveSettingsLocked(int userHandle) {
        UserInfo user = null;
        long ident = Binder.clearCallingIdentity();
        try {
            user = mUserManager.getUserInfo(userHandle);
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
        if (user != null && user.isContainer()) {
            IBinder b = ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE);
            IContainerManager containerService = IContainerManager.Stub.asInterface(b);
            final File policyFile = new File(Environment.getUserSystemDirectory(userHandle),
                    DEVICE_POLICIES_XML);
            FileInputStream stream = null;
            boolean isContainerMounted = false;
            try {
                isContainerMounted = containerService.isContainerSystemDataMounted(userHandle);
                stream = new FileInputStream(policyFile);
            } catch (RemoteException e) {
                Slog.e(TAG, "Failed talking with the Container Manager Service!", e);
            } catch (FileNotFoundException e) {
                if (isContainerMounted) {
                    /* The file does not exist yet. */
                    super.saveSettingsLocked(userHandle);
                    return;
                } else {
                    /* The file exists, but is encrypted. */
                    /* FIXME: We still need to keep track of failed attempts while
                     * the container isn't mounted. */
                    return;
                }
            } finally {
                try {
                    if (stream != null) stream.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
        super.saveSettingsLocked(userHandle);
    }
    /* End Arkham-789 */

    /* ARKHAM-545 - Disable container after reaching the maximum number of password attempts. */
    public int getMaximumFailedPasswordsForWipe(ComponentName who, int userHandle) {
        enforceCrossUserPermission(userHandle);
        synchronized (this) {
            UserInfo user = null;
            try {
                user = mUserManager.getUserInfo(userHandle);
            } catch (SecurityException e) {
                // If it fails to get user info, just go with calling the default implementation
            }
            /* Retrieve the maximum number of permitted failed attempts from the container
             * database.
             */
            if (user != null && user.isContainer()) {
                try {
                    IBinder b = ServiceManager.getService(
                            ContainerConstants.CONTAINER_MANAGER_SERVICE);
                    IContainerManager containerService = IContainerManager.Stub.asInterface(b);
                    if (containerService == null) {
                        Log.e(TAG, "Failed to retrieve a ContainerManagerService instance.");
                        return 0;
                    }
                    int max = containerService.getPasswordMaxAttempts(userHandle);
                    return max;
                } catch (RemoteException e) {
                    Slog.e(TAG, "Failed talking with the Container Manager Service!", e);
                }
            }
            return super.getMaximumFailedPasswordsForWipe(who, userHandle);
        }
    }

    protected void wipeDeviceOrUserLocked(int flags, final int userHandle) {
        UserInfo ui = mUserManager.getUserInfo(userHandle);
        final boolean isContainerUser = (ui != null && ui.isContainer());
        if (!isContainerUser) {
            super.wipeDeviceOrUserLocked(flags, userHandle);
            return;
        }
        mUserData.get(userHandle).mFailedPasswordAttempts = 0;
        try {
            IBinder b = ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE);
            IContainerManager containerService = IContainerManager.Stub.asInterface(b);
            if (containerService == null) {
                Log.e(TAG, "Failed to retrieve a ContainerManagerService instance.");
                return;
            }
            containerService.wipeOrDisableContainer(userHandle);
        } catch (RemoteException e) {
            Slog.e(TAG, "Failed talking with the Container Manager Service!", e);
        }
    }
    /* End Arkham-545 */

    /* Arkham-646: DPM lockNow command should also lock container
     * If the calling user is a container user, then lock the
     * corresponding container.
     */
    protected void lockNowUnchecked() {
        long ident = Binder.clearCallingIdentity();
        try {
            IBinder b = ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE);
            IContainerManager containerService = IContainerManager.Stub.asInterface(b);
            if (containerService != null) {
                final int callingUid = Binder.getCallingUid();
                final int userHandle = UserHandle.getUserId(callingUid);
                if (containerService.isContainerUser(userHandle)) {
                    containerService.lockContainer(userHandle);
                }
            }
        } catch (RemoteException e) {
            Slog.e(TAG, "Failed talking with the Container Manager Service!", e);
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

}

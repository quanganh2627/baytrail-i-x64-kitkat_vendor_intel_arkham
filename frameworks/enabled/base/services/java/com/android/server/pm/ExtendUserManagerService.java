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

package com.android.server.pm;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.UserInfo;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Slog;
import com.intel.arkham.ContainerConstants;
import com.intel.arkham.ContainerInfo;
import com.intel.arkham.IContainerManager;

import java.io.File;
import java.util.List;

/** {@hide} */
public class ExtendUserManagerService extends UserManagerService {
    private static final String LOG_TAG = "ExtendUserManagerService";

    private static final boolean DBG = false;
    /**
     * Available for testing purposes.
     */
    ExtendUserManagerService(File dataDir, File baseUserPath) {
        super(dataDir, baseUserPath);
    }

    /**
     * Called by package manager to create the service.  This is closely
     * associated with the package manager, and the given lock is the
     * package manager's own lock.
     */
    ExtendUserManagerService(Context context, PackageManagerService pm,
            Object installLock, Object packagesLock) {
        super(context, pm, installLock, packagesLock);
    }

     /* Arkham-353, Return the number of users that are NOT container users
     */
    protected int getRealUsersCount() {
        int num = 0;
        for (int i = 0; i < mUsers.size(); i++) {
            if (!mUsers.valueAt(i).isContainer())
                num++;
        }
        return num;
    }

    // ARKHAM-711 - disable Container Admin & ContainerLauncher for new
    // non-container users
    protected void disableApkForNonContainerUser(UserInfo userInfo, int flags) {
        if ((flags & UserInfo.FLAG_CONTAINER) == UserInfo.FLAG_CONTAINER) {
            return;
        }

        // disable Container Admin app
        mPm.setApplicationEnabledSetting(ContainerConstants.PACKAGE_DEFAULT_CONTAINER_MDM,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED, 0, userInfo.id, null);
        IContainerManager cm = getContainerManager();

        // disable ContainerLauncher
        if (cm == null) {
            Slog.w(LOG_TAG, "Unable to connect to Container Manager Service!");
            return;
        }

        try {
            List<ContainerInfo> containers = cm.listContainers();
            for (ContainerInfo cont : containers) {
                int cid = cont.getContainerId();
                mPm.setApplicationEnabledSetting(cm.getLauncherPackageName(cid),
                        PackageManager.COMPONENT_ENABLED_STATE_DISABLED, 0, userInfo.id, null);
            }
        } catch (RemoteException e) {
            Slog.w(LOG_TAG, "Failed talking to Container Manager Service!");
        }
    }

    // ARKHAM-433 call remove container function if user is container
    protected void removeUserStateLocked(final int userHandle) {
        UserInfo userInfo = getUserInfo(userHandle);
        boolean containerUnmounted = true;
        IContainerManager cm = getContainerManager();
        ContainerInfo containerInfo = null;
        int containerOwner = -1;

        if (userInfo != null && userInfo.isContainer() && cm != null) {
            try {
                containerInfo = cm.getContainerFromCid(userHandle);
                containerOwner = cm.getContainerOwnerId(userHandle);
                containerUnmounted = cm.removeContainerUser(userHandle);
            } catch (RemoteException e) {
                Slog.w(LOG_TAG, "Failed talking to Container Manager Service!");
            }
        }

        super.removeUserStateLocked(userHandle);

        // ARKHAM-661: reboot if unmounting ecryptfs failed for container
        if (!containerUnmounted && cm != null && containerInfo != null) {
            final String adminPackageName = containerInfo.getAdminPackageName();
            final UserHandle containerOwnerHandle = new UserHandle(containerOwner);
            new Thread() {
                public void run() {
                    Intent intent = new Intent(ContainerConstants.ACTION_CONTAINER_UNMOUNT_FAILED);
                    intent.setPackage(adminPackageName);
                    intent.putExtra(ContainerConstants.EXTRA_CONTAINER_ID, userHandle);
                    mContext.sendBroadcastAsUser(intent, containerOwnerHandle);
                }
            }.start();
        }
    }

    /*
     * ARKHAM-733: only unlocked containers should be visible to the system
     */
    protected boolean isContainerUserAndLocked(UserInfo userInfo) {
        IContainerManager cms = getContainerManager();
        Slog.d(LOG_TAG, "isContainerUserAndLocked userInfo " + userInfo);
        if (cms == null) {
            Slog.w(LOG_TAG, "Unable to connect to Container Manager Service!");
            return false;
        }
        try {
            return (userInfo.isContainer() && !cms.isContainerSystemDataMounted(userInfo.id));
        } catch (RemoteException e) {
            Slog.w(LOG_TAG, "Failed talking to Container Manager Service!");
        }
        return false;
    }

    private IContainerManager getContainerManager() {
        IContainerManager containerService = IContainerManager.Stub.asInterface(
                (IBinder) ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
        if (containerService == null)
            Slog.e(LOG_TAG, "Failed to retrieve a ContainerManagerService instance.");
        return containerService;
    }
}

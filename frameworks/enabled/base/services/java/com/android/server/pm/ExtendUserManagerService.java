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
import android.content.pm.PackageManager;
import android.content.pm.UserInfo;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Slog;
import android.os.IPowerManager;
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

    // ARKHAM - 353, count excluding container users.
    protected boolean isUserLimitReachedLocked() {
        int nUsers = 0;
        for (int i = 0; i < mUsers.size(); i++) {
            UserInfo ui = mUsers.valueAt(i);
            if (mRemovingUserIds.get(ui.id) || ui.isContainer())
                continue;
            nUsers++;
        }
        return nUsers >= UserManager.getMaxSupportedUsers();
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
        IContainerManager cm = IContainerManager.Stub.asInterface(
                ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));

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
    protected void removeUserStateLocked(int userHandle) {
        UserInfo userInfo = getUserInfo(userHandle);
        boolean isRebootNeeded = false;
        if (userInfo != null && userInfo.isContainer()) {
            isRebootNeeded = !removeContainerUser(userHandle);
        }

        super.removeUserStateLocked(userHandle);

        // ARKHAM-661: reboot if unmounting ecryptfs failed for container
        if (isRebootNeeded) {
           // This call waits for the reboot to complete and does not return.
           IPowerManager pm = IPowerManager.Stub.
                   asInterface(ServiceManager.getService(Context.POWER_SERVICE));
           try {
               pm.reboot(false, "Failed to unmount ecryptfs", true);
           } catch (RemoteException e) {
               Slog.w(LOG_TAG, "Failed talking to Power Manager Service!");
           }
        }
    }

    private boolean removeContainerUser(int cid) {
        IContainerManager containerService = IContainerManager.Stub.asInterface(
            ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
        if (containerService == null) {
            Slog.w(LOG_TAG, "Unable to connect to Container Manager Service!");
            return false;
        }
        try {
            containerService.removeContainerUser(cid);
        } catch (RemoteException e) {
            Slog.w(LOG_TAG, "Failed talking to Container Manager Service!");
            return false;
        }
        return true;
    }

    /*
     * ARKHAM-733: only unlocked containers should be visible to the system
     */
    protected boolean isContainerUserAndLocked(UserInfo userInfo) {
        IContainerManager cms = IContainerManager.Stub.asInterface(
            ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
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
}

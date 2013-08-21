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

import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.IBinder;
import android.os.IUserManager;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Slog;

import com.intel.arkham.ContainerConstants;
import com.intel.arkham.ContainerPolicyManager;
import com.intel.arkham.ContainerInfo;
import com.intel.arkham.IContainerManager;

import java.util.List;

/**
 * Implementation of the clipboard for copy and paste.
 */
/** {@hide} */

public class ExtendClipboardService extends ClipboardService {
    private static final String TAG = "ExtendClipboardService";
    private ContainerPolicyManager mContainerPolicyManager;

    public ExtendClipboardService(Context context) {
        super(context);
    }


    /* ARKHAM-29 - START Enforce copy-paste policy between containers
     * When setting a primary clip, put the clip into current user's clipboard
     * but also put the clip into containers allowing this operation.
     */
    private void putClip(ClipData clip, int userId) {
        PerUserClipboard clipboard = getClipboard(userId);
        clipboard.primaryClip = clip;
        final int n = clipboard.primaryClipListeners.beginBroadcast();
        for (int i = 0; i < n; i++) {
            try {
                clipboard.primaryClipListeners.getBroadcastItem(i).dispatchPrimaryClipChanged();
            } catch (RemoteException e) {
                 // The RemoteCallbackList will take care of removing
                 // the dead object for us.
                 Slog.e(TAG, "Error occured: " + e.getMessage());
            }
        }
        clipboard.primaryClipListeners.finishBroadcast();
    }

    // For ARKHAM-206
    private ContainerPolicyManager getContainerPolicyManager() {
        if (mContainerPolicyManager == null) {
            mContainerPolicyManager = ContainerPolicyManager.getInstance(mContext);
            if (mContainerPolicyManager == null) {
                Slog.e(TAG, "Can't get ContainerPolicyManagerService: is it running?",
                       new IllegalStateException("Stack trace:"));
            }
        }
        return mContainerPolicyManager;
    }

    public void setPrimaryClip(ClipData clip) {
        synchronized (this) {
            if (clip != null && clip.getItemCount() <= 0) {
                throw new IllegalArgumentException("No items");
            }
            checkDataOwnerLocked(clip, Binder.getCallingUid());
            clearActiveOwnersLocked();

            int callerId = UserHandle.getCallingUserId();

            // For current user, we put the clip data anyway
            putClip(clip, callerId);
            long token = Binder.clearCallingIdentity();
            IBinder b = ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE);
            IContainerManager containerService = IContainerManager.Stub.asInterface(b);
            IUserManager userManager = IUserManager.Stub.
                    asInterface(ServiceManager.getService(Context.USER_SERVICE));
            List<ContainerInfo> containers = null;
            try {
                // For Arkham-206 Check the outbound policy for source (if container)
                containers = containerService.listContainers();
                if (containers == null || containers.size() == 0)
                    return;

                int ownerId = UserHandle.USER_OWNER;
                ContainerInfo container = containerService.getContainerFromCid(callerId);
                ContainerPolicyManager cpm = getContainerPolicyManager();
                if (container == null) {
                    // Caller can be container owner
                    ownerId = callerId;
                } else if (cpm.getAllowCopyFromContainerForContainer(callerId)) {
                    // For Arkham-206 Put clip data into container owner
                    // if this is a container and it's policy allows copy-paste.
                    ownerId = userManager.getUserInfo(callerId).containerOwner;
                    putClip(clip, ownerId);
                } else {
                    return;
                }

                for (ContainerInfo containerInfo : containers) {
                    if (containerInfo == null)
                        continue;

                    int containerId = containerInfo.getContainerId();
                    // Check the inbound policy for target
                    if (ownerId == userManager.getUserInfo(containerId).containerOwner &&
                            cpm.getAllowCopyIntoContainerForContainer(containerId)) {
                        putClip(clip, containerId);
                    }
                }
            } catch (RemoteException e) {
                Slog.e(TAG, "Failed talking with Container Manager Service!", e);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }
    }
    // ARKHAM-29 - END
}

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

import android.accounts.Account;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Log;

import com.android.server.content.SyncQueue;
import com.android.server.content.SyncStorageEngine;
import com.intel.arkham.IContainerManager;
import com.intel.arkham.ContainerConstants;

/** {@hide} */
public abstract class ParentSyncManager {

    private static final String TAG = "ParentSyncManager";

    public ParentSyncManager(Context context, boolean factoryTest) {
        // ARKHAM-706, fix to sync container accounts after reboot
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(ContainerConstants.ACTION_CONTAINER_OPENED);
        intentFilter.addAction(ContainerConstants.ACTION_CONTAINER_DISABLED);
        context.registerReceiverAsUser(
                mUserIntentReceiver, UserHandle.ALL, intentFilter, null, null);
    }

    private BroadcastReceiver mUserIntentReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            final int userId = intent.getIntExtra(Intent.EXTRA_USER_HANDLE, UserHandle.USER_NULL);
            if (userId == UserHandle.USER_NULL) return;

            // ARKHAM-706, fix to sync container accounts after reboot
            if (ContainerConstants.ACTION_CONTAINER_OPENED.equals(action)) {
                onUserStarting(userId);
            } else if (ContainerConstants.ACTION_CONTAINER_DISABLED.equals(action)) {
                Log.i(TAG, "!@calling doDatabaseCleanup");
                getSyncStorageEngine().doDatabaseCleanup(new Account[0], userId);
                SyncQueue syncQueue = getSyncQueue();
                synchronized (syncQueue) {
                    Log.i(TAG, "!@calling syncQueue.removeUser");
                    syncQueue.removeUser(userId);
                }
            }

        }
    };

    protected abstract void onUserStarting(int userId);
    protected abstract SyncQueue getSyncQueue();
    public abstract SyncStorageEngine getSyncStorageEngine();

    /**
     * ARKHAM-477: wrapper for ContainerManagerService call
     */
    protected boolean isContainerSystemDataMounted(int cid) {
        try {
            IContainerManager containerService = IContainerManager.Stub.asInterface((IBinder)
                    ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
            if (containerService != null) {
                return containerService.isContainerSystemDataMounted(cid);
            }
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with Container Manager Service!");
        }
        return false;
    }
}

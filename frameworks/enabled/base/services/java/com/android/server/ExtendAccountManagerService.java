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
import android.content.pm.UserInfo;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Log;

import com.android.server.accounts.AccountManagerService;


/** {@hide} */
public class ExtendAccountManagerService extends AccountManagerService {

    private static final String TAG = "ExtendAccountManagerService";

    private Context mContext;
    // ARKHAM-635 - START
    // private attributes used to access CM
    private IContainerManager mContainerManager;
    // ARKHAM-635 - end

    public ExtendAccountManagerService(Context context) {
        super(context);
        mContext = context;

        // ARKHAM-773: close accounts.db when user is stopped
        IntentFilter userStopFilter = new IntentFilter();
        userStopFilter.addAction(Intent.ACTION_USER_STOPPING);
        // onUserStopping from SyncManager must be called before
        // us since it will reopen accounts.db
        userStopFilter.setPriority(IntentFilter.SYSTEM_LOW_PRIORITY);
        mContext.registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                onUserStopping(intent);
            }
        }, userStopFilter);
    }

    /**
     * Origin - ARKHAM
     * ARKHAM-635 - get a reference to the ContainerManager
     */
    private IContainerManager getContainerManager() {
        if (mContainerManager == null) {
            mContainerManager = IContainerManager.Stub.asInterface(
                    ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
        }
        return mContainerManager;
    }

    /*
     * ARKHAM-773: close accounts.db when container user is stopped
     */
    private void onUserStopping(Intent intent) {
        int userId = intent.getIntExtra(Intent.EXTRA_USER_HANDLE, -1);
        if (userId < 1) return;

        // close accounts.db only for container users
        UserInfo userInfo = getUserManager().getUserInfo(userId);
        if (!userInfo.isContainer())
            return;

        closeAccountDatabase(userId);
        synchronized (mUsers) {
            mUsers.remove(userId);
        }
    }

    protected void sendAccountsChangedBroadcast(int userId) {
        super.sendAccountsChangedBroadcast(userId);
        // ARKHAM-635 - START
        // broadcast to the container owner if the user is a container one
        IContainerManager cm = getContainerManager();
        try {
            if (cm.isContainerUser(userId)) {
                mContext.sendBroadcastAsUser(ACCOUNTS_CHANGED_INTENT,
                                new UserHandle(cm.getContainerOwnerId(userId)));
            }
        } catch (RemoteException ex) {
            Log.e(TAG, "Cannot access CM!");
        }
        // ARKHAM-635 - END
    }

    public Account[] getAccountsAsUser(String type, int userId) {
        IContainerManager cm = getContainerManager();
        boolean isContainerAccountType = ContainerConstants.ACCOUNT_TYPE_CONTAINER.equals(type);
        Account[] accounts;
        accounts = super.getAccountsAsUser((isContainerAccountType) ? null : type, userId);
        try {
            if(isContainerAccountType && !cm.isContainerUser(userId)) {
                return cm.getContainerAccounts(accounts);
            }
        } catch (RemoteException e) {
            // System is down cant do anything here.
        }
        return accounts;
    }
}

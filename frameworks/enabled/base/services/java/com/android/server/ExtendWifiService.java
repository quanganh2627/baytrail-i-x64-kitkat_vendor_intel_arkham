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

package com.android.server.wifi;

import android.app.ActivityManager;
import android.app.Notification;
import android.content.Context;
import android.content.Intent;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiStateMachine;
import android.net.wifi.WifiConfiguration;
import android.net.NetworkInfo;
import android.net.NetworkInfo.State;
import android.os.Binder;
import android.os.Handler;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Slog;

import java.util.ArrayList;
import java.util.List;

import com.android.internal.R;

import com.android.server.wifi.WifiService;
import android.os.IUserManager;
import android.content.pm.UserInfo;

/** @hide */
public final class ExtendWifiService extends WifiService {
    private static final String TAG = "ExtendWifiService";

    // ARKHAM - 621
    private IUserManager mUm;

    public ExtendWifiService(Context context) {
        super(context);
    }

    // ARKHAM-621 allow container to be able to get a valid list
    public List<ScanResult> getScanResults() {
        enforceAccessPermission();
        int userId = UserHandle.getCallingUserId();
        long ident = Binder.clearCallingIdentity();
        try {
            int currentUser = ActivityManager.getCurrentUser();
            if (userId != currentUser) {
                UserInfo userInfo = getUserManager().getUserInfo(userId);
                // FIXME: should check for containerOwner == currentUser
                if (!userInfo.isContainer())
                    return new ArrayList<ScanResult>();
                }
                return mWifiStateMachine.syncGetScanResultsList();

        } catch (RemoteException e) {
            Slog.e(TAG, "Remote Exception calling user manager", e);
            return new ArrayList<ScanResult>();
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    /**
    * ARKHAM 621 getUserManager
    */
    private IUserManager getUserManager() {
        if (mUm == null)
            mUm = IUserManager.Stub.asInterface(ServiceManager.getService(Context.USER_SERVICE));
            return mUm;
    }
}

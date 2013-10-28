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

import com.android.server.content.ContentService;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.IUserManager;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Log;
import android.util.Slog;

/** {@hide} */
public class ExtendContentService {

    private static final String TAG = "ExtendContentService";

    // ARKHAM 356
    private static IUserManager sUm;

    /**
     * ARKHAM 356, getUserManager.
     */
    private static IUserManager getUserManager() {
        if (sUm == null)
            sUm = IUserManager.Stub.asInterface(ServiceManager.getService("user"));
        if (sUm == null) Slog.e(TAG, "Failed to retrieve a UserManagerService instance.");
        return sUm;
    }

    /**
     * Check if the calling user and the user for which content
     * is requested have a container-container owner relationship.
     *
     * @param callingUser Calling user ID
     * @param userHandle User ID for which content is expected
     *
     * ARKHAM 356
     */
    public static boolean allowContainerOwnerInteraction(int callingUser, int userHandle) {
        UserInfo userInfo = null;
        long bToken = Binder.clearCallingIdentity();
        try {
            IUserManager um = getUserManager();
            if (um == null) return false;
            userInfo = um.getUserInfo(userHandle);
        } catch (RemoteException e) {
            Log.e(TAG, "Remote Exception calling user manager", e);
        } finally {
            Binder.restoreCallingIdentity(bToken);
        }
        return userInfo != null && (userInfo.isContainer()
                && userInfo.containerOwner == callingUser);
    }

}

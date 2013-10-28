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

/* @hide */

package com.android.server.am;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.AppGlobals;
import android.app.IActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.IPackageManager;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IUserManager;
import android.os.Looper;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.util.Log;
import android.util.Slog;

import com.android.internal.R;
import com.android.server.pm.UserManagerService;
import com.intel.arkham.ContainerConstants;
import com.intel.arkham.IContainerManager;


/**
 * State and management of a single stack of activities.
 */
/** {@hide} */
final class ExtendActivityStack extends ActivityStack {
    static final String TAG = ActivityManagerService.TAG;

    // ARKHAM-629 - Deactivate container based on container activity
    // Pattern to check for ContainerLauncher package name

    private int mCurrentForegroundUser;


    ExtendActivityStack(ActivityManagerService service, Context context, boolean mainStack,
            Looper looper) {
        super(service, context, mainStack, looper);
    }


    // ARKHAM-138 Allow displaying container applications from the primary user
    protected boolean okToShow(ActivityRecord r) {
        UserInfo userInfo = getUserInfoLocked(r.userId);
        if (userInfo != null && userInfo.isContainer() && mCurrentUser == userInfo.containerOwner){
            notifyUserForegroundObservers(r.userId);
            return true;
        }
        notifyUserForegroundObservers(mCurrentUser);
        return super.okToShow(r);
    }

    // ARKAHM-138 New helper function to get a reference to the UserManager service
    UserInfo getUserInfoLocked(int userId) {
        final long origId = Binder.clearCallingIdentity();
        try {
            IBinder b = ServiceManager.getService(Context.USER_SERVICE);
            UserManagerService um = (UserManagerService) IUserManager.Stub.asInterface(b);
            if (um == null) {
                Slog.e(TAG, "Failed to retrieve a UserManagerService instance.");
                return null;
            } else return um.getUserInfo(userId);
        } finally {
            Binder.restoreCallingIdentity(origId);
        }
    }

    /**
     * ARKHAM 198, Notify listeners about foreground user switch.
     */
    private void notifyUserForegroundObservers(int userId){
        if(mCurrentForegroundUser != userId){
            mCurrentForegroundUser = userId;
            ((ExtendActivityManagerService)mService).notifyUserForegroundObservers(userId);
        }
    }


    /**
     * ARKHAM-191 - Function used to determine if the top running activity is a container activity
     */
    protected boolean isTopRunningActivityinContainter(int cid) {
        ActivityRecord r = topRunningActivityLocked(null);
        if (r == null) return false;
        UserInfo ui = getUserInfoLocked(r.userId);

        if (ui != null) {
            if (((cid == 0 || cid == r.userId) && ui.isContainer())) {
                return true;
            } else if (cid > 0 && cid != r.userId && r.realActivity != null
                    && r.info.applicationInfo != null && r.info.applicationInfo.metaData!= null) {
                Bundle metaData = r.info.applicationInfo.metaData;
                int temp = metaData.getInt("containerId", -1);
                return temp != -1 && cid == temp;
           }
        }

        return false;
    }

    // ARKHAM-375. Resolve Activity in container owner space.
    protected ResolveInfo resolveParentActivity(ResolveInfo rInfo,
            int userId, Intent intent, String resolvedType)
            throws RemoteException {
        ResolveInfo info = rInfo;
        UserInfo userinfo = getUserInfoLocked(userId);
        if (rInfo == null && userinfo != null && userinfo.isContainer()) {
            IPackageManager pm = AppGlobals.getPackageManager();
            if (pm == null) return info;
            info = pm.resolveIntent(
                    intent, resolvedType,
                    PackageManager.MATCH_DEFAULT_ONLY
                    | ActivityManagerService.STOCK_PM_FLAGS, userinfo.containerOwner);
        }
        return info;
    }

    protected void checkContainerActivity(ActivityRecord next) {
        IBinder b = ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE);
        IContainerManager containerService =
                            IContainerManager.Stub.asInterface(b);
        UserInfo userInfo = getUserInfoLocked(next.userId);
        try {
            if (userInfo != null && containerService != null
                && userInfo.isContainer()
                && !containerService.isContainerActive(next.userId)) {
                    containerService.lockContainer(next.userId);
            }
        } catch (RemoteException ex) {
            Slog.e(TAG, "checkActivityOfContainer: Failed talking with CMS: ", ex);
        }
    }

    protected boolean switchUserLocked(int userId, UserStartedState uss) {
        // ARKHAM-198. Update mCurrentForegroundUser.
        mCurrentForegroundUser = userId;
        return super.switchUserLocked(userId, uss);
    }
}

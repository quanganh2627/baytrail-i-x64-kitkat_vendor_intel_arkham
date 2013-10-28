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

import android.app.ActivityManager;
import android.app.Notification;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.IUserManager;
import android.os.Process;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Slog;

/** {@hide} */
public class ExtendNotificationManagerService extends NotificationManagerService {
    private static final String TAG = "ExtendNotificationManagerService";
    private static final boolean DBG = false;

    ExtendNotificationManagerService(Context context, StatusBarManagerService statusBar,
            LightsService lights) {
        super(context, statusBar, lights);
        // ARKHAM-408: Used to get notified when an container user was removed
        // in order to
        // cancel all his notifications
        IntentFilter usrFilter = new IntentFilter(Intent.ACTION_USER_REMOVED);
        mContext.registerReceiver(mRemoveIntentReceiver, usrFilter);
    }

    private BroadcastReceiver mRemoveIntentReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();

            if (action.equals(Intent.ACTION_USER_REMOVED)) {
                int userId = intent.getIntExtra(Intent.EXTRA_USER_HANDLE, 0);
                // ARKHAM-408: cancel all active user notifications if the
                // removed user is a container one
                if (isContainerUser(userId)) {
                    cancelAllNotificationsForUser(userId);
                }
            }
        }
    };

    /*
     * ARKHAM-408: Remove all notifications that match the specified userid
     * @param userId
     */
    private void cancelAllNotificationsForUser(int userId) {
        synchronized (mNotificationList) {
            final int N = mNotificationList.size();
            boolean canceledSomething = false;
            String tagPrefix = "[" + userId + "]";
            for (int i = N - 1; i >= 0; --i) {
                NotificationRecord r = mNotificationList.get(i);
                if ((r.sbn.getTag() == null) || !r.sbn.getTag().startsWith(tagPrefix)) {
                    continue;
                }
                canceledSomething = true;
                mNotificationList.remove(i);
                cancelNotificationLocked(r, false);
            }
            if (canceledSomething) {
                updateLightsLocked();
            }
        }
    }

    // ARKHAM-160 START Notifications from container apps to be displayed in
    // container owner
    public void cancelNotificationWithTag(String pkg, String tag, int id, int userId) {
        checkCallerIsSystemOrSameApp(pkg);
        userId = ActivityManager.handleIncomingUser(Binder.getCallingPid(), Binder.getCallingUid(),
                userId, true, false, "cancelNotificationWithTag", pkg);
        if (isContainerUser(userId)) {
            tag = "[" + userId + "]" + ((tag != null) ? tag : "");
            userId = getContainerOwner(userId);
        }
        cancelNotification(pkg, tag, id, 0, Binder.getCallingUid() == Process.SYSTEM_UID ? 0
                : Notification.FLAG_FOREGROUND_SERVICE, false, userId);
    }

    // ARKHAM-160 START Notifications from container apps to be displayed in
    // container owner
    public void cancelAllNotifications(String pkg, int userId) {
        checkCallerIsSystemOrSameApp(pkg);

        userId = ActivityManager.handleIncomingUser(Binder.getCallingPid(), Binder.getCallingUid(),
                userId, true, false, "cancelAllNotifications", pkg);

        if (isContainerUser(userId)) {
            userId = getContainerOwner(userId);
        }

        // Calling from user space, don't allow the canceling of actively
        // running foreground services.
        cancelAllNotificationsInt(pkg, 0, Notification.FLAG_FOREGROUND_SERVICE, true, userId);
    }

    /**
     * ARKHAM-160 Utility method to check if a particular user is container or
     * not
     */
    @Override
    protected boolean isContainerUser(int userId) {
        IUserManager userManager = IUserManager.Stub.asInterface(ServiceManager
                .getService(Context.USER_SERVICE));
        if (userManager == null) {
            Slog.e(TAG, "Failed to retrieve a UserManager instance.");
            return false;
        }
        long ident = Binder.clearCallingIdentity();

        try {
            UserInfo userInfo = userManager.getUserInfo(userId);
            if (userInfo != null) {
                return userInfo.isContainer();
            }
        } catch (RemoteException e) {
            Slog.w(TAG, "Failed talking with User Manager Service!");
        } finally {
            Binder.restoreCallingIdentity(ident);
        }

        return false;
    }

    /**
     * ARKHAM-668 Utility method to get container owner
     */
    @Override
    protected int getContainerOwner(int userId) {
        IUserManager userManager = IUserManager.Stub.asInterface(ServiceManager
                .getService(Context.USER_SERVICE));
        if (userManager == null) {
            Slog.e(TAG, "Failed to retrieve a UserManager instance.");
            return UserHandle.USER_OWNER;
        }
        long ident = Binder.clearCallingIdentity();

        try {
            UserInfo userInfo = userManager.getUserInfo(userId);
            if (userInfo != null) {
                return userInfo.containerOwner;
            }
        } catch (RemoteException e) {
            Slog.w(TAG, "Failed talking with User Manager Service!");
        } finally {
            Binder.restoreCallingIdentity(ident);
        }

        return UserHandle.USER_OWNER;
    }

    @Override
    protected String buildNotificationTag(String tag, int userId) {
        return ("[" + userId + "]" + ((tag != null) ? tag : ""));
    }
}

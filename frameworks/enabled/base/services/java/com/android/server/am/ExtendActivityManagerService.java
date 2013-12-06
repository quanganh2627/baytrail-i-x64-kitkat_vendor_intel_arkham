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
package com.android.server.am;
import static com.android.internal.util.ArrayUtils.appendInt;

import java.util.ArrayList;
import java.util.List;

import android.app.AppGlobals;
import android.content.Context;
import android.content.Intent;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.IBinder;
import android.os.IUserManager;
import android.os.Process;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Log;
import android.util.Slog;
import com.android.server.pm.UserManagerService;

import com.intel.arkham.ContainerCommons;
import com.intel.arkham.ContainerConstants;
import com.intel.arkham.ContainerInfo;
import com.intel.arkham.IContainerManager;


/** {@hide} */
public final class ExtendActivityManagerService extends ActivityManagerService {
    private static final String DEFAULT_CONTAINER_PACKAGE = "com.android.defcontainer";

    private static final List<String> sProviders = new ArrayList<String>();
    static {
        sProviders.add("user_dictionary");
        sProviders.add("sms");
        sProviders.add("mms");
        sProviders.add("mms-sms");
    }
    private static final String PACKAGE_CONTACTS = "com.android.contacts";

    /**
     * ARKHAM - 198, Defining Interface for Foreground User Observer. Used to
     * detect when a different user comes to foreground and request focus in
     * order to reset InputMethodManager for current user.
     */
    public interface ForegroundUserObserver {
        public void userComingForeground(int userId);
    }

    /**
     * ARKHAM - 198, Foreground Observers list.
     */
    final ArrayList<ForegroundUserObserver> mForegroundUserObservers
            = new ArrayList<ForegroundUserObserver>();

    protected ExtendActivityManagerService() {
        super();
    }

    /**
     * ARKHAM - 198, currently called from within System Server, so no AIDL changes.
     */
    public void registerForegroundUserObserver(ForegroundUserObserver mObserver) {
        if (mObserver!=null)
            mForegroundUserObservers.add(mObserver);
    }

    /**
     * ARKHAM - 198, currently called from within System Server, so no AIDL changes.
     */
    public void notifyUserForegroundObservers(int userId){
        for(ForegroundUserObserver observer:mForegroundUserObservers)
            observer.userComingForeground(userId);
    }
    /**
     * ARKHAM - 198, user needs to be started for its services, receivers and providers run.
     */
    public void activateContainerUser(int userId){
        if (mStartedUsers.get(userId) == null) {
            mStartedUsers.put(userId, new UserStartedState(new UserHandle(userId), false));
            updateStartedUserArrayLocked();
        }
    }

    public ContentProviderHolder getContentProviderExternal(
            String name, int userId, IBinder token) {
        // ARKHAM-743 START: Do not allow Shell to access container's providers
        int callingUserId = UserHandle.getCallingUserId();
        int callingUid = Binder.getCallingUid();
        if (callingUserId != userId) {
            long bToken = Binder.clearCallingIdentity();
            UserInfo ui = mUserManager.getUserInfo(userId);
            Binder.restoreCallingIdentity(bToken);
            if (ui != null && ui.isContainer() && callingUid == Process.SHELL_UID) {
                throw new SecurityException(
                        String.format(
                                "ADB shell not allowed to access providers from container user %d",
                                userId));
            }
        }
        return super.getContentProviderExternal(name, userId, token);
    }


    /**
     * ARKHAM-191 - Function used to determine if the top running activity is a container activity
     */
    public boolean isTopRunningActivityInContainter(int cid) {
        return mStackSupervisor.getFocusedStack().isTopRunningActivityinContainter(cid);
    }

    protected int[] appendContainerGroupId(int uid, int[] gids) {
        int[] rGids = gids;

        // ARKHAM - 1331, 656 - Give Default Container Service access to files
        // inside the container. This is done to allow Google Play to install
        // apps inside the container.
        try {
            int packageUid = AppGlobals.getPackageManager().getPackageUid(
                    DEFAULT_CONTAINER_PACKAGE, UserHandle.USER_OWNER);
            if (uid == packageUid) {
                for (int gid = ContainerConstants.FIRST_CONTAINER_GID;
                        gid <= ContainerConstants.LAST_CONTAINER_GID; gid++) {
                    rGids = appendInt(rGids, gid);
                }
                return rGids;
            }
        } catch (RemoteException e) {
            Slog.e(TAG, "Error while adding GIDs to " + DEFAULT_CONTAINER_PACKAGE, e);
        }
        // ARKHAM - Changes end

        // ARKHAM - 125, Include container group id in process group list.int[]
        // for processes started from container
        IContainerManager containerService = getContainerManager();
        UserManagerService um = getUserManagerLocked();
        if (containerService == null || um == null) return rGids;
        int userid = UserHandle.getUserId(uid);
        UserInfo userInfo = um.getUserInfo(userid);
        if (userInfo != null && userInfo.isContainer()) {
            try {
                ContainerInfo container = containerService.getContainerFromCid(userid);
                if (container != null) rGids = appendInt(gids, container.getContainerGid());
            } catch (RemoteException e) {
                Slog.e(TAG, "appendContainerGroupId: Failed talking with CMS: ", e);
            }
        }
        // ARKHAM - Changes end.
        return rGids;
    }

    protected int processSpecialContentProviderImpl(int uid, String name) {
        // ARKHAM 356,358 - redirection request to container owner
        int userId = uid;
        long callingId = Binder.clearCallingIdentity();
        UserManagerService um = getUserManagerLocked();
        if (um == null) return userId;

        UserInfo userInfo = um.getUserInfo(userId);
        Binder.restoreCallingIdentity(callingId);
        if (userInfo != null && userInfo.isContainer()) {
            boolean switchProviderToOwner = false;
            if (sProviders.contains(name)) {
                switchProviderToOwner = true;
            } else if (name.equals(PACKAGE_CONTACTS)) {
                /* ARKHAM 824: Remove contacts merge settings from the ContainerLauncher
                 * We check for the contacts merge policy directly from the CPM. */
                int containerId = UserHandle.getUserId(Binder.getCallingUid());
                callingId = Binder.clearCallingIdentity();
                ContainerCommons.MergeContacts mc = getMergeContactsPolicy(containerId);
                Binder.restoreCallingIdentity(callingId);
                if (mc == ContainerCommons.MergeContacts.NORMAL) {
                    switchProviderToOwner = true;
                }
            }
            if (switchProviderToOwner) {
                userId = userInfo.containerOwner;
            }
        }
        // ARKHAM Changes End.
        return userId;
    }

    private ContainerCommons.MergeContacts getMergeContactsPolicy(int containerId) {
        IContainerManager containerService = getContainerManager();
        ContainerCommons.MergeContacts mergeContacts = ContainerCommons.MergeContacts.DISABLED;
        if (containerService == null) return mergeContacts;
        try {
            mergeContacts = ContainerCommons.MergeContacts.valueOf(containerService
                    .getMergeContactsPolicy(containerId));
        } catch (RemoteException e) {
        }
        return mergeContacts;
    }

    protected ContainerInfo getContainer(int userId) {
        long token = Binder.clearCallingIdentity();
        ContainerInfo container = null;
        try {
            IBinder b = ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE);
            IContainerManager containerService = getContainerManager();
            if (containerService != null) {
                // Only add calling user's recent tasks
                // Also add existing containers' recent tasks, if userId is the container owner
                container = containerService.getContainerFromCid(userId);
            }
        } catch (RemoteException e) {
            Slog.e(TAG, "getContainer: failed talking with ContainerManagerService: ", e);
        } finally {
            Binder.restoreCallingIdentity(token);
        }
        return container;
    }

    // Also add existing containers' recent tasks, if userId is the container owner
    protected boolean isUsersTask(TaskRecord tr, int userId) {
        long token = Binder.clearCallingIdentity();
        try {
            ContainerInfo container = getContainer(tr.userId);
            if (container == null)
                return super.isUsersTask(tr, userId);
            IUserManager um = IUserManager.Stub.asInterface(
                ServiceManager.getService(Context.USER_SERVICE));
            if (um == null) {
                Slog.e(TAG, "Failed to retrieve a UserManager instance.");
                return false;
            }
            int containerOwnerId = um.getUserInfo(tr.userId).containerOwner;
            if (userId == containerOwnerId)
                return true;
        } catch (RemoteException e) {
            Slog.e(TAG, "isUsersTask: failed talking with UserService: ", e);
            return super.isUsersTask(tr, userId);
        } finally {
            Binder.restoreCallingIdentity(token);
        }

        return super.isUsersTask(tr, userId);
    }

    /*
     * ARKHAM-174 - Report successful and failed attempts for container users
     * The intents coming from system processes running in container user must
     * NOT be blocked, since the container user is actually running.
     */
    protected final boolean broadcastCheckUserStopped(Intent intent, int callingUid, int userId) {
        if (userId != UserHandle.USER_ALL && mStartedUsers.get(userId) == null) {
            UserManagerService um = getUserManagerLocked();
            if (um == null) return false;
            UserInfo userInfo = um.getUserInfo(userId);
            boolean isContainerUser = false;
            if (userInfo != null && userInfo.isContainer())
                isContainerUser = true;
            // Don't skip intents from System process to
            // container users even if the container users are not yet started!
            if (callingUid != Process.SYSTEM_UID) {
                return true;
            }
            if (!isContainerUser && (intent.getFlags() & Intent.FLAG_RECEIVER_BOOT_UPGRADE) == 0) {
                return true;
            }
        }
        return false;
    }

    // ARKHAM 373 & 374 - START
    // Send ordered broadcast to primary and container users.
    protected int[] getUsersForSpecificBroadcast(int userId, boolean ordered) {
        if (!ordered)
            return super.getUsersForSpecificBroadcast(userId, ordered);

        int[] users;
        UserManagerService um = getUserManagerLocked();
        if (um == null) return new int[] {userId};;
        UserInfo userInfo = um.getUserInfo(userId);

        if (userInfo != null && userInfo.isContainer()) {
            users = new int[] {userId, userInfo.containerOwner};
        } else {
            users = new int[] {userId};
            // If userId is not a container one, scan all started users
            // list and add all container users having userId as owner
            for (int t_user : mStartedUserArray) {
                UserInfo t_userInfo = um.getUserInfo(t_user);
                if (t_user != userId && t_userInfo != null &&
                        t_userInfo.isContainer() && t_userInfo.containerOwner == userId)
                    users = appendInt(users, t_user);
            }
        }

        return users;
    }

    private IContainerManager getContainerManager() {
        IContainerManager containerService = IContainerManager.Stub.asInterface(
                (IBinder) ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
        if (containerService == null)
            Slog.e(TAG, "Failed to retrieve a ContainerManagerService instance.");
        return containerService;
    }

    @Override
    UserManagerService getUserManagerLocked() {
        UserManagerService ums = super.getUserManagerLocked();
        if (ums == null) Slog.e(TAG, "Failed to retrieve a UserManager instance.");
        return ums;
    }
}

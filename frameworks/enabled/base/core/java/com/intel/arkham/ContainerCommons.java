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

import android.app.ActivityManager;
import android.app.ActivityManagerNative;
import android.app.ActivityThread;
import android.os.IUserManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.ComponentInfo;
import android.content.pm.IPackageDataObserver;
import android.content.pm.IPackageManager;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.PackageInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.UserManager;
import android.util.Log;
import android.text.TextUtils;

import java.util.ArrayList;
import java.io.File;
import java.util.List;

public class ContainerCommons {
    private static final String TAG = "ContainerCommons";

    /**
     * Container contacts can be merged with container owner's contacts.
     * This feature has three states:
     * <p><li>DISABLED - Contacts merging is disabled
     * <li>NORMAL - Container contacts are directly merged with owner's contacts.
     * Container owner's database is used to store merged contacts
     * <li>ENCRYPTED - Container's contacts are separate from owner's contacts.
     * Container's Contacts database is encrypted.
     * When contacts are queried, a merged list is returned.
     */
    public static enum MergeContacts {
        DISABLED(0),
        NORMAL(1),
        ENCRYPTED(2);

        private int code;

        private MergeContacts(int code) {
            this.code = code;
        }

        public int getCode() {
            return code;
        }

        public static MergeContacts valueOf(int code) {
            switch(code) {
            case 0:
                return DISABLED;
            case 1:
                return NORMAL;
            case 2:
                return ENCRYPTED;
            default:
                return DISABLED;
            }
        }
        public String toString() {
            String s = super.toString();
            return s.substring(0, 1) + s.substring(1).toLowerCase();
        }
    }

    private Context mContext;
    private ActivityManager mAm;
    private PackageManager mPm;
    private IPackageManager mIPm;
    private ContainerManager mCm;
    private ContainerPolicyManager mCpm;

    /**
     * ARKHAM-226 - Add support for creating symbolic links
     * @hide
     */
    public static native int createSymLink(String oldpath, String newpath);

    static class PackageDataObserver extends IPackageDataObserver.Stub {
        @Override
        public void onRemoveCompleted(String packageName, boolean succeeded) {
        }
    }
    // Arkham-704. Need this for clearApplicationData(), cannot pass null.
    private static PackageDataObserver mPackageDataObserver = new PackageDataObserver();

    public ContainerCommons(Context context){
        mContext = context;
        mAm = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        mPm = context.getPackageManager();
        mIPm = IPackageManager.Stub.asInterface(ServiceManager.getService("package"));
        mCm = ContainerManager.getInstance(context);
        mCpm = ContainerPolicyManager.getInstance(context);
    }

    /**
     * Set up applications inside a container.
     * All the installed applications in container owner and container are
     * enabled/disabled inside the container based on the whitelist.
     * @param cid Container ID
     *
     * @hide
     */
    public void setupContainerApplications(int cid, boolean isInit) {
        if (mPm == null) {
            Log.e(TAG, "Failed to retrieve a PackageManager instance.");
            return;
        }
        List<PackageInfo> userPackageList = new ArrayList<PackageInfo>();
        boolean changed = false;
        userPackageList = mPm.getInstalledPackages(0, cid);
        if (userPackageList != null && !(userPackageList.isEmpty())) {
            for (PackageInfo pkg : userPackageList) {
                changed |= setupContainerApplication(cid, pkg.applicationInfo.packageName,
                        Integer.toString(pkg.versionCode), false, isInit);
            }
        }
        // If something has changed (an application was added to whitelist or
        // removed from whitelist, notify launchers to refresh
        if (changed) {
            notifyLaunchers();
        }
    }

    /** @hide */
    public void notifyLaunchers() {
        Intent intent = new Intent(ContainerConstants.ACTION_REFRESH_CONTAINER);
        mContext.sendBroadcastAsUser(intent, UserHandle.ALL);
    }

    /**
     * Set up an application inside a container.
     * If the application is in whitelist then enable it otherwise disable it
     * @param cid Container ID
     * @param pkgName Package name of the application
     * @param pkgVer Package version of the application
     * @param install Flag to indicate if the application should be installed first
     * @return True if any change was made
     *
     * @hide
     */
    public boolean setupContainerApplication(int cid, String pkgName, String pkgVer,
            boolean install, boolean isInit) {
        Log.d(TAG, "setupContainerApplication(cid=" + cid + ", pkgName=" + pkgName +
                ", pkgVer=" + pkgVer + ", install=" + install + ", isInit=" + isInit +")");
        if (mPm == null) {
            Log.e(TAG, "Failed to retrieve a PackageManager instance.");
            return false;
        }
        if (mCpm == null) {
            Log.e(TAG, "Failed to retrieve a ContainerPolicyManager instance.");
            return false;
        }
        String pkgOrigin = mPm.getInstallerPackageName(pkgName);
        Log.d(TAG, "Package origin: " + pkgOrigin);
        if (pkgOrigin == null)
            pkgOrigin = "";
        boolean whitelisted = mCpm.isApplicationWhiteListed(cid, pkgName
                , pkgVer, pkgOrigin);
        boolean blacklisted = false;
        // enable system apps
        if (!mCm.isApplicationRemovable(cid, pkgName)) {
            // Blacklist applicable to system whitelist only
            blacklisted = mCpm.isApplicationBlackListed(cid, pkgName);
            whitelisted = !blacklisted;
            install = true;
        }
        // enable MDM
        String containerMdmPackageName = mCm.getContainerMdmPackageName();
        if (containerMdmPackageName != null && containerMdmPackageName.equals(pkgName)) {
            whitelisted = true;
        }
        Log.d(TAG, "Package whitelisted=" + whitelisted + " blacklisted="
                + blacklisted + " install=" + install);
        PackageInfo pkg = null;
        try {
            pkg = mPm.getPackageInfo(pkgName, 0);
        } catch (NameNotFoundException e) {
            Log.w(TAG, "Package not found inside the container");
        }

        if (pkg == null) {
            if (whitelisted && install) {
                try {
                    Log.d(TAG, "Installing package to container");
                    mIPm.installExistingPackageAsUser(pkgName, cid);
                    return true;
                } catch (RemoteException e) {
                    Log.e(TAG, "failed talking with PM", e);
                }
            } else {
                Log.d(TAG, "Nothing to do");
            }
            return false;
        }

        Log.d(TAG, "Package enabled=" + pkg.applicationInfo.enabled);
        if (pkg.applicationInfo.enabled) {
            if (!whitelisted || (isInit && !install)) {
                mPm.setApplicationEnabledSetting(pkgName,
                        PackageManager.COMPONENT_ENABLED_STATE_DISABLED, 0);
                mAm.clearApplicationUserData(pkgName, mPackageDataObserver);
                return true;
            }
        } else {
            if (whitelisted && install) {
                mPm.setApplicationEnabledSetting(pkgName,
                        PackageManager.COMPONENT_ENABLED_STATE_ENABLED, 0);
                return true;
            }
        }

        if (blacklisted) {
            // Clear app data if the app is blacklisted
            mAm.clearApplicationUserData(pkgName, mPackageDataObserver);
        }
        return false;
    }

    /**
     * Enable an app for a user.
     * Caller may require INTERACT_ACROSS_USER permission, if uid != myUid
     * @param pkgName App package name
     * @param uid User ID
     *
     * @hide
     */
    public static void enableApplicationForUser(String pkgName, int uid) throws RemoteException {
        ActivityThread.getPackageManager().setApplicationEnabledSetting(pkgName,
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED, 0 , uid, null);
    }

    /**
     * Disable an app for a user
     * Caller may require INTERACT_ACROSS_USER permission, if uid != myUid
     * @param pkgName App package name
     * @param uid User ID
     *
     * @hide
     */
    public static void disableApplicationForUser(String pkgName, int uid) throws RemoteException {
        ActivityThread.getPackageManager().setApplicationEnabledSetting(pkgName,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED, 0 , uid, null);
    }

    /**
     * Utility method to clear data of an application
     * Caller may require INTERACT_ACROSS_USER permission, if uid != myUid
     * @param cid Container ID
     * @param pkgName Package whose data is to be cleared
     *
     * @hide
     */
    public static void clearApplicationData(int cid, String pkgName) throws RemoteException {
        ActivityManagerNative.getDefault().clearApplicationUserData(pkgName,
                mPackageDataObserver, cid);
    }

    /** @hide */
    public static PackageInfo getPackageInfo(String pkgName, int uid) throws RemoteException {
        return ActivityThread.getPackageManager().getPackageInfo(pkgName, 0, uid);
    }

    /**
     * ARKHAM-100 - START Add support for Container Launcher App.
     * called from ContainerInfo.java
     *
     * @hide
     */
    public static CharSequence getContainerLabel(ComponentInfo ci, PackageManager pm) {
        boolean isContainerApp = false;
        ApplicationInfo ai = ci.applicationInfo;
        if (ai != null) {
            Bundle md = ai.metaData;
            int cid;
            isContainerApp =  md !=null && (cid = md.getInt("containerId", -1)) != -1;
            if(isContainerApp){
                String containerName = null;
                String sDir = ai.sourceDir;
                // Parse the containerName from apk filename
                // TODO: UGLY. Get name from CMS.
                int from = sDir.lastIndexOf('-');
                if (from > 0) {
                    int to = sDir.indexOf('[', ++from);
                    if (to > 0) {
                        containerName = sDir.substring(from, to);
                    }
                }
                if (containerName != null) {
                    CharSequence label;
                    if (ci.labelRes != 0) {
                        label = pm.getText(ci.packageName, ci.labelRes, ai);
                        if (label != null) {
                            return TextUtils.concat(containerName, " " + label);
                        }
                    }
                    if (ai.nonLocalizedLabel != null) {
                        return TextUtils.concat(containerName, ai.nonLocalizedLabel);
                    }
                    if (ai.labelRes != 0) {
                        label = pm.getText(ci.packageName, ai.labelRes, ai);
                        if (label != null) {
                            return TextUtils.concat(containerName, " " + label);
                        }
                    }
                    return TextUtils.concat(containerName, " " + ci.name);
                }
            }
        }
        return null;
    }

    /**
     * ARKHAM-100 - Add support for Container Launcher App
     * If the package identifies a container launcher app, append _container_id
     * to it's pkgName, so we can have the same package installed and running for
     * multiple containers.
     * Called from PackageParser.java
     *
     * @hide
     */
    public static String getContainerId(File sourceFile) {
        String parent = sourceFile.getParent();
        boolean isContainerApp = (parent != null && parent.equals("/data/containers"));
        String pkgName = null;
        if(isContainerApp){
            String sDir = sourceFile.getName();
            int from = sDir.lastIndexOf('[');
            if (from > 0) {
                int to = sDir.indexOf(']', ++from);
                if (to > 0) {
                    pkgName = "_container_" + sDir.substring(from, to);
                }
            }
        }
        return pkgName;
    }

    /** @hide */
    public static boolean isTopRunningActivityInContainer(int cid) throws RemoteException {
        IBinder b = ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE);
        IContainerManager containerManager = IContainerManager.Stub.asInterface(b);
        if (containerManager == null) {
            return false;
        }
        return containerManager.isTopRunningActivityInContainer(cid);
    }

    /** @hide */
    public static boolean isContainerUser(Context context, int userId) {
        ContainerManager containerManager =  ContainerManager.getInstance(context);
        if (containerManager == null) {
            return false;
        }
        return containerManager.isContainerUser(userId);
    }

    /** @hide */
    public static String getContainerName(Context context, int userId) {
        String name = null;
        ContainerManager cm = ContainerManager.getInstance(context);
        if (cm != null) {
            ContainerInfo cn = cm.getContainerFromCid(userId);
            if (cn != null) {
                name = cn.getContainerName();
                return " [" + name + "]";
            }
        }
        return "";
    }

    /** @hide */
    public static boolean isContainer(Context context) {
        UserManager um = (UserManager) context.getSystemService(Context.USER_SERVICE);
        if (um == null) {
            return false;
        }
        long token = Binder.clearCallingIdentity();
        UserInfo userInfo = um.getUserInfo(UserHandle.myUserId());
        Binder.restoreCallingIdentity(token);
        if (userInfo == null)
            return false;
        return userInfo.isContainer();
    }

    /** @hide */
    public static boolean isContainer(int user) {
        IUserManager um = IUserManager.Stub.asInterface(ServiceManager.
                getService(Context.USER_SERVICE));
        if (um == null) {
            return false;
        }
        try {
            UserInfo ui = um.getUserInfo(user);
            if (ui != null)
                return ui.isContainer();
        } catch (RemoteException e) {
        }
        return false;
    }

    /**
     * ARKHAM-844: Log a stacktrace for data folder accesses when container is not mounted
     *
     * @hide
     */
    public static void logContainerUnmountedAccess(int userId, String path) {
        String systemBooted = SystemProperties.get("service.bootanim.exit", null);
        if (systemBooted == null || !systemBooted.equals("1"))
            return;
        IContainerManager containerService = IContainerManager.Stub.asInterface(
            (IBinder) ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
        if (containerService == null)
            return;
        try {
            containerService.logContainerUnmountedAccess(userId, path);
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with Container Manager Service!", e);
        }
    }

    /**
     * Method to return if an account belongs to an unmounted container
     *
     * @hide
     */
    public static boolean isUnmountedContainerAccount(String accountName) {
        IContainerManager cm = IContainerManager.Stub.asInterface(
                ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
        if (cm == null) {
            return false;
        }
        try {
            int cid = cm.isContainerAccount(accountName);
            return cid > 0 && !cm.isContainerOpened(cid) && !cm.isContainerDisabled(cid);
        } catch (RemoteException e) {
            Log.e(TAG, "Error connecting to ContainerManagerService");
        }
        return false;
    }

}

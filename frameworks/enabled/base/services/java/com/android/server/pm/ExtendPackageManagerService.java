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

/** {@hide} */
package com.android.server.pm;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DEFAULT;
import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
import android.content.pm.PackageParser;
import android.content.pm.ResolveInfo;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.Environment;
import android.os.FileObserver;
import android.os.Handler;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Log;
import android.util.Slog;
import android.util.Xml;

import com.android.internal.R;
import com.intel.arkham.ContainerConstants;
import com.intel.arkham.IContainerManager;

import java.io.File;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.Set;

import org.xmlpull.v1.XmlPullParser;

/** {@hide} */
public class ExtendPackageManagerService extends PackageManagerService {
    static final String TAG = "ExtendPackageManagerService";

    // ARKHAM-197 - Relink packages after container is unlocked (and decrypted)
    final FileObserver mContainerAppInstallObserver;

    // ARKHAM - 100, File path for container launcher.
    final File mContainerAppDir;

    // ARKHAM - 100, File path for container launcher.
    HashSet<PackageParser.Package> mReLinkPackages = null;

    private static final String PATH_CONTAINER_DIR = "containers";

    // ARKHAM-903: used to detect launcher package
    private Pattern mLauncherPackagePattern;

    public ExtendPackageManagerService(Context context, Installer installer,
            boolean factoryTest, boolean onlyCore) {
        super(context, installer, factoryTest, onlyCore);
        Slog.v(TAG, "ExtendPackageManagerService init");

        File dataDir = Environment.getDataDirectory();
        mContainerAppDir = new File(dataDir, PATH_CONTAINER_DIR);

        synchronized (mInstallLock) {
            // writer
            synchronized (mPackages) {
                int scanMode = PackageManagerService.SCAN_MONITOR
                        | PackageManagerService.SCAN_NO_PATHS
                        | PackageManagerService.SCAN_DEFER_DEX
                        | PackageManagerService.SCAN_BOOTING;
                if (mNoDexOpt) {
                    Slog.w(TAG, "Running ENG build: no pre-dexopt!");
                    scanMode |= PackageManagerService.SCAN_NO_DEX;
                }

                if (!onlyCore) {
                    // ARKHAM-100, initilizing mContainerAppInstallObserver.

                    // ARKHAM-123 Use symbolic links for the ContainerLauncher.apk instead of
                    // copying it. Since the container launchers are created as symbolic links,
                    // we must add FileObserver.CREATE as an observer event, so that they are
                    // recognized immediately.
                    mContainerAppInstallObserver = new PackageManagerService.AppDirObserver(
                        mContainerAppDir.getPath(), OBSERVER_EVENTS | FileObserver.CREATE, false);
                    mContainerAppInstallObserver.startWatching();
                    scanDirLI(mContainerAppDir, 0, scanMode, 0);

                } else {
                    // Arkham - 100, do not include container launcher in core apps.
                    mContainerAppInstallObserver = null;
                }
            }
        }
    }


    /**
     * ARKHAM - 197, rescan packages for the container user, after opening the container.
     */
    public void reScanMissedPackages(int userId) {
        mContext.enforceCallingOrSelfPermission(android.Manifest.permission.INSTALL_PACKAGES, null);
        synchronized (mInstallLock) {
        synchronized (mPackages) {
            mSettings.readPackageRestrictionsLPr(userId);

            if (mReLinkPackages == null || mReLinkPackages.isEmpty())
                return;
            Iterator<PackageParser.Package> it = mReLinkPackages.iterator();
            while (it.hasNext()) {
                PackageParser.Package pkg = it.next();
                Slog.i(TAG, "Linking native library dir '" + pkg.applicationInfo.nativeLibraryDir
                        + "' (user=" + userId + ")");
                if (mInstaller.linkNativeLibraryDirectory(pkg.packageName,
                            pkg.applicationInfo.nativeLibraryDir, userId) < 0) {
                    Slog.w(TAG, "Failed linking native library dir (user=" + userId
                            + ")");
                }
            }
            mSettings.writePackageRestrictionsLPr(userId);
        } // synchronized (mPackages)
        } // synchronized (mInstallLock)
    }



    @Override
    public ResolveInfo resolveIntent(Intent intent, String resolvedType,
            int flags, int userId) {
        if (!sUserManager.exists(userId)) return null;

        // ARKHAM - 375, Adding exception to expand container visibility till its owner
        int callingUserId = UserHandle.getUserId(Binder.getCallingUid());
        long identity = Binder.clearCallingIdentity();
        UserInfo userInfo = sUserManager.getUserInfo(callingUserId);
        if (userInfo != null && !(userInfo.isContainer() && userInfo.containerOwner == userId))
            Binder.restoreCallingIdentity(identity);
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, "resolve intent");
        // ARKHAM Change ends.

        List<ResolveInfo> query = queryIntentActivities(intent, resolvedType, flags, userId);
        // Restore the binder if this is a container request.
        boolean containerRequest = userInfo != null &&
                userInfo.isContainer() && userInfo.containerOwner == userId;
        if (containerRequest)
            Binder.restoreCallingIdentity(identity);

        // ARKHAM - filter out non-system apps while extending resolve area to container owner.
        // Vendor apps are also considered as system apps.
        if (query != null && containerRequest) {
            for (ResolveInfo resolveInfo : query) {
                if (resolveInfo.activityInfo != null
                    && !isSystemApp(resolveInfo.activityInfo.applicationInfo)) {
                    query.remove(resolveInfo);
                }
            }
        }
        // ARKHAM - Change Ends
        return chooseBestActivity(intent, resolvedType, flags, query, userId);
    }

    /* ARKHAM-38 When installing from /data/containers Check if the
     * APK is properly formated for a container launcher and if so
     * extract the container id. If container id is null then we
     * forbid instalation of this APK. */
    protected boolean isContainerLauncher(File scanFile) {
        if (mContainerAppDir != null && scanFile.getParent().equals(mContainerAppDir.getPath()))
            return true;
        return false;
    }

    protected String getContainerId(File scanFile) {
        String containerId = null;
        String sDir = scanFile.getName();
        int from = sDir.lastIndexOf('[');
        if (from > 0) {
            int to = sDir.indexOf(']', ++from);
            if (to > 0) {
                containerId = sDir.substring(from, to);
            }
        }
        return containerId;
    }

    @Override
    protected boolean processPackageInContainer(int userId, PackageParser.Package pkg) {
        UserInfo usr = sUserManager.getUserInfo(userId);
        Slog.v(TAG, "checkSpecialCase");
        if (!usr.isContainer()) {
            return false;
        } else {
            if (mReLinkPackages == null) {
                mReLinkPackages = new HashSet<PackageParser.Package>();
            }
            mReLinkPackages.add(pkg);
            return true;
        }
    }

    @Override
    protected boolean checkEventType(int event) {
       // ARKHAM-123 Use symbolic links for the ContainerLauncher.apk instead of copying it
        if (super.checkEventType(event)) return true;
        if ((event&(FileObserver.CREATE)) != 0)  return true;
        return false;
    }

    // ARKHAM-441 Disable package verification for containers to allow
    // the MDM to manage side-loaded applications without user interaction.
    @Override
    protected boolean isVerificationEnabled(int userId, int flags) {
        UserInfo usr = sUserManager.getUserInfo(userId);
        if (usr.isContainer()) {
            return false;
        }
        return super.isVerificationEnabled(userId, flags);
    }

    /**
     * ARKHAM-903: used to change authority for providers from container
     * launcher package, by appending "_container_{containerId}" suffix, in
     * order to have different providers for each container
     * @param authority
     * @param packageName
     * @return
     */
    protected String fixAuthority(String authority, String packageName) {
        // Use lazy instantiation because fixAuthority is called from superclass
        // when scanning package in constructor
        if (mLauncherPackagePattern == null) {
            // ARKHAM-903: used to detect launcher package
            mLauncherPackagePattern = Pattern.compile(ContainerConstants.ContainerPackageRegexp);
        }
        if (authority != null && mLauncherPackagePattern.matcher(packageName).find()) {
            int from = packageName.lastIndexOf("_");
            int containerId = Integer.parseInt(packageName.substring(++from, packageName.length()));

            String names[] = authority.split(";");
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < names.length; ++i) {
                if (i > 0) {
                    sb.append(";");
                }
                sb.append(String.format("%s_container_%s", names[i], containerId));
            }
            return sb.toString();
        }
        return authority;
    }

    @Override
    public void setApplicationEnabledSetting(String appPackageName,
            int newState, int flags, int userId, String callingPackage) {
        super.setApplicationEnabledSetting(appPackageName, newState, flags, userId, callingPackage);

        // ARKHAM-978 START If an app other that container's MDM is trying to enable
        // and app inside the container then notify container MDM
        long identity = Binder.clearCallingIdentity();
        UserInfo userInfo = null;
        try {
            userInfo = sUserManager.getUserInfo(userId);
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
        if ((userInfo != null && userInfo.isContainer())
                && (newState == COMPONENT_ENABLED_STATE_ENABLED
                || newState == COMPONENT_ENABLED_STATE_DEFAULT)) {
            // Get container MDM package
            int callingUid = Binder.getCallingUid();
            IContainerManager cm = IContainerManager.Stub.asInterface(
                    ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
            String containerMdmPackage = null;
            try {
                containerMdmPackage = cm.getContainerMdmPackageName();
            } catch (RemoteException e) {
                Log.e(TAG, "Can't connect to ContainerManagerService");
            }

            if (containerMdmPackage != null) {
                identity = Binder.clearCallingIdentity();
                try {
                    // Check if the calling package is container MDM
                    PackageInfo contMdmPI = getPackageInfo(containerMdmPackage, 0, userId);
                    if (contMdmPI != null && contMdmPI.applicationInfo.uid != callingUid) {
                        Log.d(TAG, "Unauthorized appplication trying to enable container apps");
                        Intent intent = new Intent(ContainerConstants.ACTION_APP_ENABLED);
                        PackageInfo packageInfo = getPackageInfo(appPackageName, 0, userId);
                        intent.putExtra(ContainerConstants.EXTRA_PACKAGE_INFO, packageInfo);
                        mContext.sendBroadcastAsUser(intent, new UserHandle(userId));
                    }
                } finally {
                    Binder.restoreCallingIdentity(identity);
                }
            }
            // ARKHAM-978 END
        }
    }
}

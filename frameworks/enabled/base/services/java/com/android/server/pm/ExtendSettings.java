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

package com.android.server.pm;

import android.content.Context;
import android.content.pm.PackageManager;
import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.IUserManager;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Log;
import android.util.Slog;
import android.util.Xml;

import com.intel.arkham.IContainerManager;
import com.intel.arkham.ContainerConstants;

import java.io.File;
import java.util.Map;
import java.util.Set;

import org.xmlpull.v1.XmlPullParser;

/**
 * Holds information about dynamic settings.
 */
/** {@hide} */
final class ExtendSettings extends Settings {
    private static final String TAG = "ExtendPackageSettings";

    ExtendSettings(Context context) {
        super(context);
    }

    ExtendSettings(Context context, File dataDir) {
        super(context,dataDir);
    }

    // ARKHAM-433 call createcontainer for container users
    void createNewUserLILPw(PackageManagerService service, Installer installer, UserInfo userInfo,
            File path) {
        Slog.w(TAG, "createNewUserLILPw ");
        if (userInfo.isContainer()) {
            createContainerUser(userInfo);
        }
        super.createNewUserLILPw(service, installer, userInfo, path);
    }


    // ARKHAM-433 BEGIN
    private boolean createContainerUser(UserInfo userInfo) {
        IContainerManager containerService = IContainerManager.Stub.asInterface(
            ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
        if (containerService == null) {
            Slog.w(TAG, "Unable to connect to Container Manager Service!");
            return false;
        }
        int ret = -1;
        try {
            ret = containerService.createContainerUser(userInfo.id, userInfo.name);
        } catch (RemoteException e) {
            Slog.w(TAG, "Failed talking to Container Manager Service!");
        }
        if(ret != 0) {
            Log.w(TAG, "Failed to create container user " + userInfo.id + "!");
            return false;
        }
        return true;
    }
    // ARKHAM-433 END

    private UserInfo getUserInfo(int userId) {
        IUserManager userManager =
                IUserManager.Stub.asInterface(ServiceManager.getService(Context.USER_SERVICE));
        long ident = Binder.clearCallingIdentity();
        UserInfo userInfo = null;

        try {
            userInfo = userManager.getUserInfo(userId);
        } catch (RemoteException e) {
            Slog.w(TAG, "Failed talking with User Manager Service!");
        } finally {
            Binder.restoreCallingIdentity(ident);
        }

        return userInfo;
    }
}

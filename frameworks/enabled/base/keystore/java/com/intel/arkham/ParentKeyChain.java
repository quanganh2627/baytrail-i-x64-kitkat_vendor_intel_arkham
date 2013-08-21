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

import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Log;

import java.io.File;

import org.apache.harmony.xnet.provider.jsse.TrustedCertificateStore;

public class ParentKeyChain {
    private static final String TAG = "KeyChain";

    // ARKHAM-624 CA store paths for container users
    private static final String CA_CERTS_DIR_SYSTEM = "/etc/security/cacerts";
    private static final String CA_USER_CERTS_DIR_ADDED
            = "/user/%d/com.android.keychain/keychain/cacerts-added";
    private static final String CA_USER_CERTS_DIR_DELETED
            = "/user/%d/com.android.keychain/keychain/cacerts-removed";


    /**
     * ARKHAM-624: Return a new instantiated TrustedCertificateStore
     * depending on callingUserId.  If the calling user is a container
     * one, change the CA user storage base dir to
     * "/data/user/{userId}/com.android.keychain/", otherwise use the
     * default one "/data/misc/keychain"
     * @hide
     */
    public static TrustedCertificateStore getTrustedCertificateStore() {
        int userId = UserHandle.getCallingUserId();
        IContainerManager containerService = IContainerManager.Stub.asInterface(
                ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
        boolean isContainer = false;
        if (containerService != null) {
            try {
                isContainer = containerService.isContainerUser(userId);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        TrustedCertificateStore store;
        if (isContainer) {
            final String rootPath = System.getenv("ANDROID_ROOT");
            final String dataPath = System.getenv("ANDROID_DATA");
            store = new TrustedCertificateStore(new File(rootPath
                    + CA_CERTS_DIR_SYSTEM), new File(dataPath
                    + String.format(CA_USER_CERTS_DIR_ADDED, userId)),
                    new File(dataPath
                            + String.format(CA_USER_CERTS_DIR_DELETED, userId)));
        } else {
            store = new TrustedCertificateStore();
        }
        return store;
    }
}

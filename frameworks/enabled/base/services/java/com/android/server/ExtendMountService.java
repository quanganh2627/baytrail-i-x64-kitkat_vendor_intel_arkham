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


import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.storage.IMountService;
import android.util.Slog;
import android.util.Xml;



import java.io.File;
import java.util.Map;

import javax.crypto.SecretKey;

import com.intel.arkham.IContainerManager;
import com.intel.arkham.ContainerConstants;

/**
 * MountService implements back-end services for platform storage
 * management.
 * @hide - Applications should use android.os.storage.StorageManager
 * to access the MountService.
 */
/** {@hide} */

class ExtendMountService extends MountService
        implements INativeDaemonConnectorCallbacks, Watchdog.Monitor {

    private static final boolean DEBUG_EVENTS = true;

    public static final int EssKeyResult = 113;
    private static final String TAG = "ExtendMountService";
    private static final String VOLD_TAG = "VoldConnector";

    ExtendMountService(Context context) {
        super(context);
    }

    public int encryptStorage(String password) {
        int ret;

        /* For ARKHAM-425 Lock and unmount containers before starting the encryption process */
        IContainerManager containerService = IContainerManager.Stub.asInterface((IBinder)
                ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
        try {
            ret = containerService.unmountInternalStorageForAllContainers();
        } catch (RemoteException e) {
            ret = -1;
        }
        if (ret != 0) {
            Slog.e(TAG, "Failed to unmount container. Error returned: " + ret);
            return ret;
        }

        return super.encryptStorage(password);
    }
}

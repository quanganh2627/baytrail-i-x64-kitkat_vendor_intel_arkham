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

import android.content.Context;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageManager;
import android.os.RemoteException;

import java.io.File;

public class ContainerCommons {

    public static String getContainerId(File sourceFile) {
        return null;
    }

    public static CharSequence getContainerLabel(ComponentInfo ci, PackageManager pm) {
        return null;
    }

    public static boolean isContainerUser(Context context, int userId) {
        return false;
    }

    public static boolean isContainer(Context context) {
        return false;
    }

    public static boolean isContainer(int user) {
        return false;
    }

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

    public static String getContainerName(Context context, int userId) {
        return "";
    }

    public static boolean isTopRunningActivityInContainer(int cid) throws RemoteException {
        return false;
    }

    public static void logContainerUnmountedAccess(int userId, String path) {
    }
}

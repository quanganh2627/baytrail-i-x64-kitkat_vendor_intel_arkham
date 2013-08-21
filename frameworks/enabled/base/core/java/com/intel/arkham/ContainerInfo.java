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

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Information about a container. This class contains details such as
 * container ID, name, GID, disabled state info, container MDM package name.
 */
public class ContainerInfo implements Parcelable {
    private int containerId;
    private String containerName;
    private String adminPackageName;
    private int containerGid;
    private boolean isDisabled;

    public ContainerInfo(int containerId, String containerName, String adminPackageName,
            int containerGid, boolean isDisabled) {
        this.containerId = containerId;
        this.containerName = containerName;
        this.adminPackageName = adminPackageName;
        this.containerGid = containerGid;
        this.isDisabled = isDisabled;
    }

    public ContainerInfo(Parcel source) {
        containerId = source.readInt();
        containerName = source.readString();
        adminPackageName = source.readString();
        containerGid = source.readInt();
        isDisabled = source.readInt() == 1;
    }

    public ContainerInfo(int cid, Parcel source) {
        containerId = cid;
        containerName = source.readString();
        adminPackageName = source.readString();
        containerGid = source.readInt();
        isDisabled = source.readInt() == 1;

    }

    public int getContainerId() {
        return containerId;
    }

    public String getContainerName() {
        return containerName;
    }

    public String getAdminPackageName() {
        return adminPackageName;
    }

    public int getContainerGid() {
        return containerGid;
    }

    public boolean getDisabledState() {
        return isDisabled;
    }

    public void setDisabledState(boolean disabled) {
        isDisabled = disabled;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(containerId);
        dest.writeString(containerName);
        dest.writeString(adminPackageName);
        dest.writeInt(containerGid);
        dest.writeInt(isDisabled ? 1 : 0);
    }

    public static void writeToParcel(ContainerInfo container, Parcel dest) {
        if (container != null) {
            container.writeToParcel(dest, 0);
        } else {
            dest.writeInt(-1);
        }
    }

    public static ContainerInfo readFromParcel(Parcel source) {
        int cid = source.readInt();
        return cid != -1 ? new ContainerInfo(cid, source) : null;
    }

    public static final Parcelable.Creator<ContainerInfo> CREATOR
            = new Parcelable.Creator<ContainerInfo>() {

        @Override
        public ContainerInfo createFromParcel(Parcel source) {
            return new ContainerInfo(source);
        }

        @Override
        public ContainerInfo[] newArray(int size) {
            return new ContainerInfo[size];
        }
    };
}

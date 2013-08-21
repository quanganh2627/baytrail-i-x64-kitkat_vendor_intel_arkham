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

public abstract class ParentUserInfo {

    /**
     * ARKHAM - 23, Indicates a container user.
     */
    public static final int FLAG_CONTAINER   = 0x80000000;
    // ARKHAM - 347, -4 for non-container user.-4 because -1, -2, -3 are used in UserHandle.
    public int containerOwner = -4;

    /**
     * ARKHAM - 23, function to identify if the user is container user.
     * @hide
     */
    public boolean isContainer() {
        return (getFlags() & FLAG_CONTAINER) == FLAG_CONTAINER;
    }

    protected abstract int getFlags();

    public ParentUserInfo() {
    }

    public ParentUserInfo(ParentUserInfo orig) {
        // ARKHAM 347
        containerOwner = orig.containerOwner;
    }

    public void writeToParcel(Parcel dest, int parcelableFlags) {
        // ARKHAM - 347
        dest.writeInt(containerOwner);
    }

    protected ParentUserInfo(Parcel source) {
        // ARKHAM - 347
        containerOwner = source.readInt();
    }
}

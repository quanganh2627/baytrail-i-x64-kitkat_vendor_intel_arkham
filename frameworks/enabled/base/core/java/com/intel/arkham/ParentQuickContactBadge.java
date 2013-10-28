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
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.provider.ContactsContract;

import java.util.List;

/** @hide */
public class ParentQuickContactBadge {

    // ARKHAM-406 Differentiate primary and container contacts
    private boolean isContainerContact = false;
    private Drawable mContainerOverlay;

    public ParentQuickContactBadge() {
    }

    public void drawableStateChanged(Drawable mOverlay, int[] drawableState) {
        if (mOverlay != null && mOverlay.isStateful()) {
            // ARKHAM-406 Differentiate primary and container contacts
            if (mContainerOverlay != null && mContainerOverlay.isStateful()) {
                mContainerOverlay.setState(drawableState);
            }
        }
    }

    public void onContainerDraw(Canvas canvas, int width, int height, int mPaddingTop,
            int mPaddingLeft) {
        // ARKHAM-828: Draw mContainerOverlay if not null and if it's a container contact
        boolean drawContainerOverlay = isContainerContact && (mContainerOverlay != null);

        // ARKHAM-406 Differentiate primary and container contacts
        if (drawContainerOverlay)
            mContainerOverlay.setBounds(0, 0, width / 2, height / 2);

        if (mPaddingTop == 0 && mPaddingLeft == 0) {
            if (drawContainerOverlay) mContainerOverlay.draw(canvas);
        } else {
            int saveCount = canvas.getSaveCount();
            canvas.save();
            canvas.translate(mPaddingLeft, mPaddingTop);
            if (drawContainerOverlay) mContainerOverlay.draw(canvas);
            canvas.restoreToCount(saveCount);
        }
    }

    // ARKHAM-406 Differentiate primary and container contacts
    private void loadContainerIcon(Uri contactUri, Context context) {
        final PackageManager pm = context.getPackageManager();
        ContainerInfo containerInfo = resolveContainer(contactUri, context);
        if (containerInfo != null) {
            String containerPackage = containerInfo.getAdminPackageName();
            try {
                mContainerOverlay = pm.getApplicationIcon(containerPackage);
            } catch (NameNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    // Find out which container this contact belongs to
    private ContainerInfo resolveContainer(Uri contactUri, Context context) {
        if (contactUri == null || contactUri.getPathSegments() == null) {
            return null;
        }
        List<String> segments = contactUri.getPathSegments();
        /** Getting the 4-th element in the list (0..3) */
        String idSegment = (segments.size() >= 4 ? segments.get(3) : null);
        if (idSegment != null) {
            long cid = Long.parseLong(idSegment) / ContainerConstants.CONTAINER_CONTACTID_OFFSET;
            if (ContactsContract.isProfileId(cid)) {
                return null;
            }
            ContainerManager cm = new ContainerManager(context);
            return cm.getContainerFromCid((int)cid);
        }
        return null;
    }
    // END ARKHAM-406

    public void onContactUriChanged(Uri contactUri, Context context) {
        if (resolveContainer(contactUri, context) != null) {
            isContainerContact = true;
            loadContainerIcon(contactUri, context);
        } else {
            isContainerContact = false;
            // If the new contact doesn't belong to a container, hide the
            // container icon overlay, if present.
            if (mContainerOverlay != null) {
                mContainerOverlay.setVisible(false, false);
                mContainerOverlay = null;
            }
        }
    }
}

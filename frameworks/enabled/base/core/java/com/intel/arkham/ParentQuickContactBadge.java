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

public class ParentQuickContactBadge {

    private static final int CONTAINER_ID_OFFSET = 1000000;
    private static final int BASE_CID = 10;

    // ARKHAM-406 Differentiate primary and container contacts
    private boolean isContainerContact = false;
    private Drawable containerOverlay;

    public ParentQuickContactBadge() {
    }

    public void drawableStateChanged(Drawable mOverlay, int[] drawableState) {
        if (mOverlay != null && mOverlay.isStateful()) {
            // ARKHAM-406 Differentiate primary and container contacts
            if (containerOverlay != null && containerOverlay.isStateful()) {
                containerOverlay.setState(drawableState);
            }
        }
    }

    public void onContainerDraw(Canvas canvas, int width, int height, int mPaddingTop,
            int mPaddingLeft) {
        // ARKHAM-828: Draw containerOverlay if not null and if it's a container
        // contact
        boolean drawContainerOverlay = isContainerContact && (containerOverlay != null);

        // ARKHAM-406 Differentiate primary and container contacts
        if (drawContainerOverlay)
            containerOverlay.setBounds(0, 0, width / 2, height / 2);

        if (mPaddingTop == 0 && mPaddingLeft == 0) {
            if (drawContainerOverlay) containerOverlay.draw(canvas);
        } else {
            int saveCount = canvas.getSaveCount();
            canvas.save();
            canvas.translate(mPaddingLeft, mPaddingTop);
            if (drawContainerOverlay) containerOverlay.draw(canvas);
            canvas.restoreToCount(saveCount);
        }
    }

    public void assignContactUri(Uri contactUri){
        // ARKHAM-406 Differentiate primary and container contacts
        if (contactUri != null) {
            List<String> uriSegments = contactUri.getPathSegments();
            // Manually dialed numbers will send URIs with the following format:
            // .../phone_lookup/<phone number>
            if (!uriSegments.get(0).equals("phone_lookup") && uriSegments.size() > 3) {
                // Contacts called from the Phone/People apps will
                // send URIs with the following format:
                // .../contacts/lookup/<internalID/<contactID>/...
                String contactIDSegment = uriSegments.get(3);
                long contactId = Long.parseLong(contactIDSegment);
                if (!ContactsContract.isProfileId(contactId) &&
                        contactId >= (CONTAINER_ID_OFFSET * BASE_CID)) {
                    isContainerContact = true;
                }
            }
        }
        // END ARKHAM-406
    }

    // ARKHAM-406 Differentiate primary and container contacts
    private void loadContainerIcon(Uri contactUri, Context context) {
        final PackageManager pm = context.getPackageManager();
        ContainerInfo containerInfo = resolveContainer(contactUri, context);
        if (containerInfo != null) {
            String containerPackage = containerInfo.getAdminPackageName();
            try {
                containerOverlay = pm.getApplicationIcon(containerPackage);
            } catch (NameNotFoundException e) {
                e.printStackTrace();
            }
        } // TODO: load a placeholder icon if container isn't found?
    }

    // Find out which container this contact belongs to
    private ContainerInfo resolveContainer(Uri contactUri, Context context) {
        String idSegment = contactUri.getPathSegments().get(3);
        if (idSegment != null) {
            long cid = Long.parseLong(idSegment) / CONTAINER_ID_OFFSET;
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
        if (isContainerContact) {
            loadContainerIcon(contactUri, context);
        }
    }
}

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
import android.util.Log;
import android.os.ServiceManager;
import java.util.Map;
import java.util.List;
import android.os.RemoteException;


/**
 * Public interface for managing container policies.
 */
public class ContainerPolicyManager {

    private static String TAG = "ContainerPolicyManager";
     /*
     * @hide
     */
    public static final String ACTION_CONTAINER_POLICY_MANAGER_STATE_CHANGED =
        "com.intel.arkham.CONTAINER_POLICY_MANAGER_STATE_CHANGED";

    public static final int TIMEOUT_TYPE_CONTAINER_ACTIVITY = 0;
    public static final int TIMEOUT_TYPE_DEVICE_ACTIVITY = 1;

    private final Context mContext;
    private final IContainerPolicyManager mService;
    private static ContainerPolicyManager sInstance;

    private ContainerPolicyManager (Context context) {
        mContext = context;
        mService = IContainerPolicyManager.Stub.asInterface(ServiceManager
                .getService(ContainerConstants.CONTAINER_POLICY_SERVICE));
    }

    /** Registered and initialized inside Context
     */
    /** @hide */
    public static ContainerPolicyManager getInstance(Context context) {
        if (sInstance == null)
            sInstance = new ContainerPolicyManager(context);
        return sInstance.mService != null ? sInstance : null;
    }

    /**
     * Determine whether or not copy to clipboard is allowed from container.
     * If yes, then the content is also copied to container owner's clipboard and
     * other containers' clipboard provided their policy allows it.
     */
    public boolean getAllowCopyFromContainer() {
        boolean ret = false;
        if (mService != null) {
            try {
                ret = mService.getAllowCopyFromContainer();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Called by MDM app inside the container to set the outward copy policy.
     * @param value Whether or not copy is allowed from the container
     */
    public void setAllowCopyFromContainer(boolean value) {
        if (mService != null) {
            try {
                mService.setAllowCopyFromContainer(value);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
    }

    /**
     * Determine whether or not copy into container is allowed.
     * If yes, then the content copied inside container owner and
     * other containers is available inside this container.
     */
    public boolean getAllowCopyIntoContainer() {
        boolean ret = false;
        if (mService != null) {
            try {
                ret = mService.getAllowCopyIntoContainer();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Called by MDM app inside the container to set inward copy policy
     * @param value Whether or not copy is allowed inside container
     */
    public void setAllowCopyIntoContainer(boolean value) {
        if (mService != null) {
            try {
                mService.setAllowCopyIntoContainer(value);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
    }

    /**
     * Returns whether container's calendar data is exported outside the container or not
     */
    public boolean getExportCalendarAcrossUsers() {
        boolean ret = false;
        if (mService != null) {
            try {
                ret = mService.getExportCalendarAcrossUsers();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Called by MDM inside the container to set the calendar export policy
     * @param value Calendar export policy value
     */
    public void setExportCalendarAcrossUsers(boolean value) {
        if (mService != null) {
            try {
                mService.setExportCalendarAcrossUsers(value);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
    }

    /**
     * Returns whether container's email data is exported outside the container or not
     */
    public boolean getExportEmailContentAcrossUsers() {
        boolean ret = false;
        if (mService != null) {
            try {
                ret = mService.getExportEmailContentAcrossUsers();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Called by MDM inside the container to set the email export policy
     * @param value Email export policy value
     */
    public void setExportEmailContentAcrossUsers(boolean value) {
        if (mService != null) {
            try {
                mService.setExportEmailContentAcrossUsers(value);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
    }

    /**
     * Returns password timeout value.
     * After timer expires, the container is locked.
     */
    public long getContainerLockTimeout() {
        long ret = 0;
        if (mService != null) {
            try {
                ret = mService.getContainerLockTimeout();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Returns password timeout type. Possible values are:
     * <li>CONTAINER: Timeout is based on container activity
     * <li>DEVICE: Timeout is based on device activity
     */
    public int getContainerLockTimeoutType() {
        int ret = 0;
        if (mService != null) {
            try {
                ret = mService.getContainerLockTimeoutType();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * MDM inside the container calls this API to set password timeout value and type
     * @param value Timeout value
     * @param type Timeout type
     */
    public void setContainerLockTimeout(long value, int type) {
        if (mService != null) {
            try {
                mService.setContainerLockTimeout(value, type);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
    }

    /**
     * Get a whitelist of applications which can be installed/enabled inside a container.
     * The returned Map contains package name as key and version/apk source as value.
     */
    public Map getApplicationWhiteList() {
        Map ret = null;
        if (mService != null) {
            try {
                ret = mService.getApplicationWhiteList();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Set a container's application whitelist
     * @param appWhiteList Map with package name as key and version/apk source as value
     */
    public void setApplicationWhiteList(Map appWhiteList) {
        if (mService != null) {
            try {
                mService.setApplicationWhiteList(appWhiteList);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
    }

    /**
     * Get a container's application blacklist.
     * Blacklist overrides system whitelist.
     * Blacklist should be used very carefully by MDM apps because
     * it removes apps from the system whitelist which may destabilize the container.
     */
    public List getSystemBlackList() {
        List ret = null;
        if (mService != null) {
            try {
                ret = mService.getSystemBlackList();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Set container's blacklist policy
     * @param systemBlackList List of apps present in system whitelist
     * which should not be enabled inside the container.
     * This list is a list of package names.
     */
    public void setSystemBlackList(List systemBlackList) {
        if (mService != null) {
            try {
                mService.setSystemBlackList(systemBlackList);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
    }

    /**
     * Utility API for system to get container's list of contacts
     * fields that should be visible in the merged contacts.
     * @return The list of fields that are visible in the merged
     * contacts. This is a list of Strings containing the mime types
     * identifying the contacts fields.
     */
    public List getContactFieldWhiteList() {
        List ret = null;
        if (mService != null) {
            try {
                ret = mService.getContactFieldWhiteList();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Set container's list of contacts fields that should be visible
     * in the merged contacts.
     * @param contactFieldWhiteList the list of fields to be visible
     * in the merged contacts. This is a list of Strings containing
     * the mime types identifying the contacts fields.
     */
    public void setContactFieldWhiteList(List contactFieldWhiteList) {
        if (mService != null) {
            try {
                mService.setContactFieldWhiteList(contactFieldWhiteList);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
    }

    /**
     * Utility API for system to get export clipboard policy for a container.
     * See {@link #getAllowCopyFromContainer()} for more details
     * @param cid Container ID
     */
    public boolean getAllowCopyFromContainerForContainer(int cid) {
        boolean ret = false;
        if (mService != null) {
            try {
                ret = mService.getAllowCopyFromContainerForContainer(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Utility API for system to get import clipboard policy for a container.
     * See {@link #getAllowCopyIntoContainer()} for more details
     * @param cid Container ID
     */
    public boolean getAllowCopyIntoContainerForContainer(int cid){
        boolean ret = false;
        if (mService != null) {
            try {
                ret = mService.getAllowCopyIntoContainerForContainer(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Utility API for system to get container's list of contacts
     * fields that should be visible in the merged contacts. See
     * {@link #getContactFieldWhiteList} for more details.
     * @param cid the Container ID
     */
    public List getContactFieldWhiteListForContainer(int cid) {
        List ret = null;
        if (mService != null) {
            try {
                ret = mService.getContactFieldWhiteListForContainer(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Returns if an application is whitelisted or not for a container
     * @param cid Container ID
     * @param pkgName Package name of the application
     * @param pkgVersion Package version
     * @param pkgOrigin Apk source
     */
    public boolean isApplicationWhiteListed(int cid, String pkgName,
            String pkgVersion, String pkgOrigin) {
        boolean ret = false;
        if (mService != null) {
            try {
                ret = mService.isApplicationWhiteListed(cid, pkgName,
                        pkgVersion, pkgOrigin);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }

    /**
     * Returns if an application is blacklisted or not for a container
     * @param cid Container ID
     * @param pkgName Package name of the application
     */
    public boolean isApplicationBlackListed(int cid, String pkgName) {
        boolean ret = false;
        if (mService != null) {
            try {
                ret = mService.isApplicationBlackListed(cid, pkgName);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container policy service", e);
            }
        }
        return ret;
    }
}

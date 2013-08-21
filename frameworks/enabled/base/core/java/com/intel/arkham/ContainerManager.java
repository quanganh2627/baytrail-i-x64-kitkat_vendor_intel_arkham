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

import java.util.List;

import android.accounts.Account;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Log;

/**
 * Public interface for managing containers on the device.
 */
public class ContainerManager {
    private static String TAG = "ContainerManager";

    /**
     * Container launcher package prefix
     */
    private static final String CONTAINER_PACKAGE_NAME = "com.intel.arkham.app_container_";

    public static final int CONTAINER_TYPE_PERSONAL = 0;
    public static final int CONTAINER_TYPE_ENTERPRISE = 1;

    private final Context mContext;
    private final IContainerManager mService;
    private static ContainerManager sInstance;

    /**
     * Get the package name of the launcher application associated with a container
     * @param cid Container ID
     * @return Container launcher package name
     */
    public static String getContainerLauncherPkgName(int cid) {
        return CONTAINER_PACKAGE_NAME + cid;
    }

    /**
     * Container Manager constructor
     * @param context
     */
    public ContainerManager(Context context) {
        mContext = context;
        mService = IContainerManager.Stub.asInterface(
                       ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
    }

    /**
     * Singleton method
     * @hide
     */
    public static ContainerManager getInstance(Context context) {
        if (sInstance == null)
            sInstance = new ContainerManager(context);
        return sInstance.mService != null ? sInstance : null;
    }

    /**
     * Create a container with given specifications
     * @param containerType Container type. Personal or enterprise.
     * @param options Options
     * @param containerName Container name
     * @param bundle Container policy bundle
     * @return ID of the created container or error code if container creation failed
     */
    public int createContainer(int containerType, int options, String containerName,
            Bundle bundle) {
        if (mService != null) {
            try {
                return mService.createContainer(containerType, options, containerName,
                        mContext.getPackageName(), bundle);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return ContainerConstants.ERROR_NO_SERVICE;
    }

    /**
     * Get container details from container ID
     * @param cid ID of the container
     * @return {@link ContainerInfo} object containing details of the container
     */
    public ContainerInfo getContainerFromCid(int cid) {
        if (mService != null) {
            try {
                return mService.getContainerFromCid(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }

    /**
     * Get container details from container group ID
     * @param cGid Container's group ID
     * @return {@link ContainerInfo} object containing details of the container
     */
    public ContainerInfo getContainerFromCGid(int cGid) {
        if (mService != null) {
            try {
                return mService.getContainerFromCGid(cGid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }

    /**
     * Get container details from container name
     * @param containerName Container name
     * @return {@link ContainerInfo} object containing details of the container
     */
    public ContainerInfo getContainerFromName(String containerName) {
        if (mService != null) {
            try {
                return mService.getContainerFromName(containerName);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }

    /**
     * Get container's launcher application's package name
     * @param cid Container ID
     * @return Package name of container launcher
     */
    public String getLauncherPackageName(int cid) {
        if (mService != null) {
            try {
                return mService.getLauncherPackageName(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }

    /**
     * Enable a disabled container. Only container's MDM can enable a container.
     * @return Result of enabling request
     */
    public boolean enableContainer() {
        if (mService != null) {
            try {
                return mService.enableContainer();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Disable a container. Only container's MDM can disable a container.
     * @return Result of disabling request
     */
    public boolean disableContainer() {
        if (mService != null) {
            try {
                return mService.disableContainer();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Remove a container and wipe all its data.
     * Only container's MDM can remove a container.
     */
    public void removeContainer() {
        if (mService != null) {
            try {
                mService.removeContainer(0);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
    }

    /**
     * Remove a container and wipe all its data.
     * Only container's MDM can remove a container.
     * @param cid ID of the container to be removed.
     */
    public void removeContainer(int cid) {
        if (mService != null) {
            try {
                mService.removeContainer(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
    }

    /**
     * Unlock a container. This method can be called only from Settings UI.
     * @param passwordHash Container password hash
     * @return Result of unlock request
     */
    public int unlockContainer(byte[] passwordHash) {
        int ret = ContainerConstants.NO_ERROR;
        if (mService != null) {
            try {
                ret = mService.unlockContainer(passwordHash, UserHandle.myUserId());
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
                ret = ContainerConstants.ERROR_NO_SERVICE;
            }
        }
        return ret;
    }

    /**
     * Lock a container. User must verify the password to access the container again.
     * @param cid Container ID
     */
    public void lockContainer(int cid) {
        if (mService != null) {
            try {
                mService.lockContainer(cid);
            } catch( RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
    }

    /**
     * Change container password. This function can be called only from Settings UI.
     * @param cid Container ID
     * @param newPasswordHash New container password hash
     * @param passwordType Password type. It can be alphanumeric, numeric, pattern etc.
     * @return Status of the change password request
     */
    public boolean changePassword(int cid, byte[] newPasswordHash, int passwordType) {
        if (mService != null) {
            try {
                return mService.changePassword(cid, newPasswordHash, passwordType);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * List all the containers present on the device
     * @return List of all containers
     */
    public List<ContainerInfo> listContainers() {
        if (mService != null) {
            try {
                return mService.listContainers();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }

    /**
     * Get container owner's user ID
     * @param cid Container ID
     * @return Owner's user ID
     */
    public int getContainerOwnerId(int cid) {
        if (mService != null) {
            try {
                return mService.getContainerOwnerId(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return UserHandle.USER_OWNER;
    }

    /**
     * Install an application to the container
     * @param cid ID of the container in which application is to be installed
     * @param apkFilePath Path of the apk file to be installed
     * @return Result code
     */
    public int installApplicationToContainer(int cid, String apkFilePath) {
        if (mService != null) {
            try {
                return mService.installApplicationToContainer(cid, apkFilePath);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return ContainerConstants.ERROR_NO_SERVICE;
    }

    /**
     * Install an application to the container.
     * This call must originate from inside the container
     * @param apkFilePath Path of the apk file to be installed
     */
    public void installApplication(String apkFilePath) {
        if (mService != null) {
            try {
                mService.installApplication(apkFilePath);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
    }

    /**
     * Install an application already installed in the container owner, inside a container
     * @param cid Container ID
     * @param pkgName Package name of the application
     * @return Result code
     */
    public int installOwnerUserApplication(int cid, String pkgName) {
        if (mService != null) {
            try {
                return mService.installOwnerUserApplication(cid, pkgName);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return ContainerConstants.ERROR_NO_SERVICE;
    }

    /**
     * Returns if the application can be removed from container launcher.
     * An application cannot be removed from the container launcher if
     * it is a part of the system whitelist.
     * @param cid Container ID
     * @param pkgName Application package
     * @return true if the application can be removed from container launcher
     */
    public boolean isApplicationRemovable(int cid, String pkgName) {
        if (mService != null) {
            try {
                return mService.isApplicationRemovable(cid, pkgName);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Remove an application from the container launcher.
     * @param cid Container ID
     * @param pkgName Package name of the application to be removed
     * @return Result code
     */
    public int removeApplication(int cid, String pkgName) {
        if (mService != null) {
            try {
                return mService.removeApplication(cid, pkgName);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return ContainerConstants.ERROR_NO_SERVICE;
    }

    /**
     * Returns true if the container is active.
     * Active means that container is unlocked and it can be used by the user.
     * @param cid Container ID
     * @return True if the container is active.
     */
    public boolean isContainerActive(int cid) {
        if (mService != null) {
            try {
                return mService.isContainerActive(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Returns true if the container is opened during boot atleast once.
     * Opened means that container is unlocked atleast once after reboot.
     * @param cid Container ID
     * @return True if the container is active.
     */
    public boolean isContainerOpened(int cid) {
        if (mService != null) {
            try {
                return mService.isContainerOpened(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Returns true if the container is disabled
     * @return True if the container is disabled
     */
    public boolean isContainerDisabled() {
        return isContainerDisabled(UserHandle.myUserId());
    }

    /**
     * Returns true if the container is disabled
     * @param cid Container ID
     * @return True if the container is disabled
     */
    public boolean isContainerDisabled(int cid) {
        if (mService != null) {
            try {
                return mService.isContainerDisabled(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Returns true if the container is initialized.
     * This means that container password must be set.
     * @param cid Container ID
     * @return True if the container is initialized.
     */
    public boolean isContainerInitialized(int cid) {
        if (mService != null) {
            try {
                return mService.isContainerInitialized(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Sets container's policies. A policy bundle containing all the policies is passed.
     * This API should be called by container owner's MDM.
     * @param cid Container ID
     * @param bundle Container policy bundle
     * @return True if policy is successfully applied
     */
    public int setContainerPolicy(int cid, Bundle bundle) {
        if (mService != null) {
            try {
                return mService.setContainerPolicy(cid, bundle);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return ContainerConstants.ERROR_NO_SERVICE;
    }

    /**
     * Notify the primary user MDM when container state changes
     * State changes include all the DeviceAdminReceiver callbacks
     * This API can only be called by MDM present inside a container
     * @param intent Intent to be broadcasted
     * @return True if the broadcast succeeded
     */
    public boolean sendDeviceAdminBroadcast(Intent intent) {
        if (mService != null && intent != null) {
            try {
                return mService.sendDeviceAdminBroadcast(intent);
            } catch( RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Result of the policies sent back to the container's MDM
     * This result policy bundle is generated inside the container and
     * it contains status of all the policies that were applied by the MDM.
     * @param cid Container ID
     * @param result Result policy bundle
     */
    public void policyUpdateResult(int cid, Bundle result) {
        if (mService != null) {
            try {
                mService.policyUpdateResult(cid, result);
            } catch( RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
    }

    /**
     * Returns true if the user is a container user
     * @param userId User ID to be checked
     * @return True if the user is a container
     * @hide
     */
    public boolean isContainerUser(int userId) {
        if (mService != null) {
            try {
                return mService.isContainerUser(userId);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Returns the package name of MDM inside the container
     */
    public String getContainerMdmPackageName(){
        if (mService != null) {
            try {
                return mService.getContainerMdmPackageName();
            } catch( RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }

    public boolean isTopRunningActivityInContainer(int cid) {
        if (mService != null) {
            try {
                return mService.isTopRunningActivityInContainer(cid);
            } catch(RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Get container's contacts merging policy.
     * This policy has three values:
     * <p><li>DISABLED - Contacts merging is disabled
     * <li>NORMAL - Container contacts are directly merged with owner's contacts.
     * Container owner's database is used to store merged contacts
     * <li>ENCRYPTED - Container's contacts are separate from owner's contacts.
     * Container's Contacts database is encrypted.
     * When contacts are queried, a merged list is returned.
     */
    public ContainerCommons.MergeContacts getMergeContactsPolicy(int cid) {
        ContainerCommons.MergeContacts ret = ContainerCommons.MergeContacts.DISABLED;
        if (mService != null) {
            try {
                ret = ContainerCommons.MergeContacts.valueOf(mService.getMergeContactsPolicy(cid));
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return ret;
    }

    public boolean setMergeContactsPolicy(int cid, ContainerCommons.MergeContacts policy) {
        if (mService != null) {
            try {
                return mService.setMergeContactsPolicy(cid, policy.getCode());
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    public String getLauncherBackgroundImagePath(int cid) {
        if (mService != null) {
            try {
                return mService.getLauncherBackgroundImagePath(cid);
            } catch(RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }

    public boolean setLauncherBackgroundImagePath(int cid, String imagePath) {
        if (mService != null) {
            try {
                return mService.setLauncherBackgroundImagePath(cid, imagePath);
            } catch(RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    public void actionLauncherBackgroundSet(int cid) {
        if (mService != null) {
            try {
                mService.actionLauncherBackgroundSet(cid);
            } catch(RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
    }

    public int getPasswordMaxAttempts(int cid) {
        if (mService != null) {
            try {
                return mService.getPasswordMaxAttempts(cid);
            } catch(RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return ContainerConstants.ERROR_NO_SERVICE;
    }

    public boolean setPasswordMaxAttempts(int cid, int maximum) {
        if (mService != null) {
            try {
                return mService.setPasswordMaxAttempts(cid, maximum);
            } catch(RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    public String getPasswordMaxAttemptsAction(int cid) {
        if (mService != null) {
            try {
                return mService.getPasswordMaxAttemptsAction(cid);
            } catch(RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }

    public boolean setPasswordMaxAttemptsAction(int cid, String action) {
        if (mService != null) {
            try {
                return mService.setPasswordMaxAttemptsAction(cid, action);
            } catch(RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /** Called by MDM whenever password expiring callback is received
     * @param cid
     * @param message Notification title
     * @param contentText Notification description
     */
    public void actionPasswordExpiring(int cid, String message, String contentText) {
        if (mService != null) {
            try {
                mService.actionPasswordExpiring(cid, message, contentText);
            } catch( RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
    }

    /**
     * Called by MDM whenever password change callback is received
     * @param cid
     */
    public void actionPasswordChanged(int cid) {
        if (mService != null) {
            try {
                mService.actionPasswordChanged(cid);
            } catch( RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
    }

    /**
     * Origin - ARKHAM
     * ARKHAM-635 - get primary user and all container accounts
     */
    public Account[] getContainerAccounts(Account[] accounts) {
        if (mService != null) {
            try {
                mService.getContainerAccounts(accounts);
            } catch(RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }
}

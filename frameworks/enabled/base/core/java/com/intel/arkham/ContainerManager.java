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
import android.content.pm.ActivityInfo;
import android.os.Bundle;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Log;

/**
 * <p>A Container is a special class of Android user which provides IPC and filesystem isolation
 * as well as filesystem encryption. Container applications run in the same user interface with
 * the owner of the container, i.e. no user switch is required. Container Manager is the service
 * that provides APIs to manage the container (e.g. create, wipe, enable, disable).</p>
 *
 * <a name="Creating a container"></a>
 * <h3>Creating a container</h3>
 * <ol>
 *   <li>Before creating the container, the MDM application must register as a
 *       <a href="{@docRoot}guide/topics/admin/device-admin.html">device administrator</a>.
 *       Only device administrators are allowed to create a container.</li>
 *   <li><p>To create a container, the MDM application must call {@link #createContainer}.</p>
 *       <p>The Settings application will be started so that the user can set a password for the
 *       container.
 *       The options available for setting the password are restricted to the ones specified by the
 *       container policy. At this point, the container is created but not completely initialized
 *       until a password is set.</p>
 *       <p>If the user does not set a password (cancels the process or reboots the device),
 *       the container will not be ready to use. The MDM application can check the state of the
 *       container by calling {@link #isContainerInitialized}. To continue the container
 *       creation in this case, the MDM application must call {@link #createContainer} again.
 *       The creation process will continue with restarting the Settings application.<p></li>
 *   <li>Once a password is set for the container, the Container Manager Service will finish
 *       initialization.
 *       Intent {@link com.intel.arkham.ContainerConstants#ACTION_CONTAINER_CREATED} will be
 *       send to the MDM application once this is complete and the container is ready to use.</li>
 * </ol>
 * <a name="Managing the container"></a>
 * <h3>Managing the container</h3>
 *
 * <p> After creation, a container is by default enabled. While enabled, essentially
 * it can have three states: </p>
 * <ul>
 *  <li> Locked and encrypted (right after a reboot) </li>
 *  <li> Locked and unencrypted (when locked explicitly by user or by lock
 *       timeout) </li>
 *  <li> Unlocked and implicitly unencrypted</li>
 * </ul>
 * <p> If container is disabled, container is automatically encrypted. No actions
 * can be performed while container is disabled, but wiping it or enabling it
 * back. </p>
 * <p> Bellow are a set of actions which can be performed over the container in
 * order to manage it: </p>
 * <ul>
 *  <li> Disable/Enable the container by calling
 *      {@link com.intel.arkham.ContainerManager#enableContainer()} /
 *      {@link com.intel.arkham.ContainerManager#disableContainer()}. </li>
 *  <li> Wipe the container by calling
 *      {@link com.intel.arkham.ContainerManager#removeContainer(int cid)}. This can be
 *      called in any container state (enabled or disabled). </li>
 *  <li> Set/Change container's policy (whitelisted apps, merge contacts mode
 *      etc.) by calling
 *      {@link com.intel.arkham.ContainerManager#setContainerPolicy(int cid, Bundle bundle)} </li>
 *  <li> Change the background image for ContainerLauncher by calling
 *      {@link com.intel.arkham.ContainerManager#setLauncherBackgroundImagePath(int cid,
 *              String imagePath)} </li>
 *  <li> Install/Delete side loaded applications by calling
 *      {@link com.intel.arkham.ContainerManager#installApplicationToContainer(int cid,
 *              String apkFilePath)}/
 *      {@link com.intel.arkham.ContainerManager#removeApplication(int cid, String pkgName)} </li>
 * </ul>
 */
public class ContainerManager {
    private static String TAG = "ContainerManager";

    /**
     * Container launcher package prefix
     * @hide
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
     * @hide
     */
    public static String getContainerLauncherPkgName(int cid) {
        return CONTAINER_PACKAGE_NAME + cid;
    }

    /**
     * Container Manager constructor
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
     * Creates a container.
     *
     * @param containerType [not used] Container type, Personal or Enterprise
     * @param options [not used] Options
     * @param containerName Container name
     * @param bundle Container policy see {@link #setContainerPolicy(int, Bundle)} for an example
     *          how to create it
     * @return ID of the created container or a negative value representing the error occurred,
     *      see the ERROR_* constants from {@link ContainerConstants}
     *
     * @see #setContainerPolicy(int, Bundle)
     * @see com.intel.arkham.ContainerConstants
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
     * Retrieves container information based on its ID.
     *
     * @param cid ID of the container
     * @return {@link ContainerInfo} object containing details of the container
     *
     * @see com.intel.arkham.ContainerInfo
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
     * @hide
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
     * Retrieves container information based on its name.
     *
     * @param containerName Container name
     * @return {@link ContainerInfo} object containing details of the container
     *
     * @see com.intel.arkham.ContainerInfo
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
     * @hide
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
     * Enables a disabled container.
     * Only container's MDM can enable a container.
     * @return True if the container was enabled
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
     * Disables an enabled container.
     * Only container's MDM can disable a container.
     * @return True if the container was disabled
     */
    public boolean disableContainer() {
        if (mService != null) {
            try {
                return mService.disableContainer(0);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Removes a container and wipe all its data.
     * Only container's MDM can remove a container.
     * @hide
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
     * Removes a container and wipe all its data.
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
     * Wipes or disables a container according to its administrator's policy.
     * @param cid ID of the container to be wiped/disabled.
     * @return Returns true if the operation succeeded or false otherwise
     * @hide
     */
    public boolean wipeOrDisableContainer(int cid) {
        if (mService != null) {
            try {
                return mService.wipeOrDisableContainer(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Unlock a container. This method can be called only from Settings UI.
     * @param passwordHash Container password hash
     * @return Result of unlock request
     * @hide
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
     * Locks a container.
     * User must provide the password to access the container again.
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
     * @hide
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
     * @hide
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
     * @hide
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
     * Installs an application to the container.
     * @param cid ID of the container in which application is to be installed
     * @param apkFilePath Path of the apk file to be installed
     * @return On success ContainerConstants.NO_ERROR, on error one of the ERROR_
     *      constants defined in {@link ContainerConstants}
     *
     * @see com.intel.arkham.ContainerConstants
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
     * Installs an application to the container.
     * This call must originate from inside the container
     * @param apkFilePath Path of the apk file to be installed
     * @hide
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
     * @hide
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
     * Checks if the application can be removed from container launcher.
     * An application cannot be removed from the container launcher if
     * it is a part of the system whitelist.
     * @param cid Container ID
     * @param pkgName Application package name
     * @return True if the application can be removed from container launcher, false otherwise
     * @hide
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
     * Removes an application from the container.
     * @param cid Container ID
     * @param pkgName Package name of the application to be removed
     * @return On success ContainerConstants.NO_ERROR, on error one of the ERROR_
     *      constants defined in {@link ContainerConstants}
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
     * Checks if the container is active.
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
     * Checks if the container is opened during boot at least once.
     * Opened means that container is unlocked at least once after reboot.
     * @param cid Container ID
     * @return True if the container is opened.
     * @hide
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
     * Checks if the container is disabled.
     * @return True if the container is disabled
     * @hide
     */
    public boolean isContainerDisabled() {
        return isContainerDisabled(UserHandle.myUserId());
    }

    /**
     * Checks if the container is disabled.
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
     * Checks if the container is initialized.
     * This means that container password must be set.
     * @param cid Container ID
     * @return True if the container is initialized
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
     * Sets container's policies.
     * This API should be called by container owner's MDM.
     * @param cid Container ID
     * @param bundle Container policy
     * @return On success ContainerConstants.NO_ERROR, on error one of the ERROR_
     *      constants defined in {@link ContainerConstants}
     *
     * <p><br>
     * A policy bundle contains all the rules that will be applied
     * to the container and will regulate its functionality.
     *
     * <br>The bundle may contain the following keys:
     * <p><ul>
     * <li> {@code ContainerConstants.POLICY_PASSWORD_QUALITY} of type {@code int}
     * <li> {@code ContainerConstants.POLICY_ALLOW_COPY_INTO_CONTAINER} of type {@code boolean}
     * <li> {@code ContainerConstants.POLICY_ALLOW_COPY_FROM_CONTAINER} of type {@code boolean}
     * <li> {@code ContainerConstants.POLICY_CONTAINER_LOCK_TIMEOUT} of type {@code long}
     * <li> {@code ContainerConstants.POLICY_CONTAINER_LOCK_TIMEOUT_TYPE} of type {@code int}
     * <li> {@code ContainerConstants.POLICY_PASSWORD_EXPIRATION_TIMEOUT} of type {@code long}
     * <li> {@code ContainerConstants.POLICY_MAX_FAILED_PASSWORDS_FOR_WIPE} of type {@code int}
     * <li> {@code ContainerConstants.POLICY_MAX_FAILED_PASSWORDS_FOR_DISABLE} of type {@code int}
     * <li> {@code ContainerConstants.POLICY_MERGE_CONTACTS_PROVIDER} of type {@code int}
     * <li> {@code ContainerConstants.POLICY_PASSWORD_HISTORY_LENGTH} of type {@code int}
     * <li> {@code ContainerConstants.POLICY_APP_WHITE_LIST} of type {@code Bundle}, see below
     * <li> {@code ContainerConstants.POLICY_SYSTEM_BLACK_LIST} of type {@code ArrayList<String>}
     * <li> {@code ContainerConstants.POLICY_CONTACT_FIELD_WHITE_LIST} of
     *      type {@code ArrayList<String>}
     * </ul></p>
     *
     * <br><p>The bundle for POLICY_APP_WHITE_LIST policy contains only keys of type String.
     * Here is an example how to create a policy:<br>
     * <pre>
     *    Bundle policy = new Bundle();
     *    policy.putInt(POLICY_PASSWORD_QUALITY, DevicePolicyManager.PASSWORD_QUALITY_ALPHANUMERIC);
     *    policy.putBoolean(POLICY_ALLOW_COPY_INTO_CONTAINER, false);
     *
     *    Bundle whiteList = new Bundle();
     *    {@code for (Map.Entry<String, String> entry : mWhitelist.entrySet()) {}
     *        whiteList.putString(entry.getKey(), entry.getValue());
     *    }
     *    policy.putBundle(POLICY_APP_WHITE_LIST, whiteList);
     * </pre>
     * <br><p> The application whitelist is a {@code HashMap<String, String>} with package names as
     * keys and string values of form 'pkgName + "/" + pkgSource'
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
     * Notifies the primary user MDM when container state changes.
     * State changes include all the DeviceAdminReceiver callbacks.
     * This API can only be called by MDM present inside a container.
     * @param intent Intent to be broadcasted
     * @return True if the broadcast succeeded
     * @hide
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
     * Result of the policies sent back to the container's MDM.
     * This result policy bundle is generated inside the container and
     * it contains status of all the policies that were applied by the MDM.
     * @param cid Container ID
     * @param result Result policy bundle
     * @hide
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
     * Returns the package name of MDM inside the container.
     * @hide
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

     /**
     * Check if the main running activity is from a container or not.
     * @param cid ContainerID
     * @return true if the main running activity is from a container
     * @hide
     */
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
     * @param cid ContainerID
     * @return policy
     * @hide
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

   /**
   * Sets the container's policy regarding merging the contacts within the container
   * with the primary user's contacts.
   * This policy has three values:
   * <p><li>DISABLED - Contacts merging is disabled</li>
   * <li>NORMAL - Container contacts are directly merged with owner's contacts.
   * Container owner's database is used to store merged contacts</li>
   * <li>ENCRYPTED - Container's contacts are separate from owner's contacts.
   * Container's Contacts database is encrypted.
   * When contacts are queried, a merged list is returned.</li>
   * @param cid Container ID
   * @param policy The merging policy to apply
   * @return True if the new policy was applied, false otherwise
   * @hide
   */
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

    /**
     * Returns the background image that is set in the launcher.
     * @param cid ContainerID
     * @hide
     */
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

    /**
     * Sets the container's launcher background image.
     * @param cid Container ID
     * @param imagePath The path to a file containing the background image to be applied in the
     *      container launcher
     * @return True if the background image was applied
     */
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

    /** @hide */
    public void actionLauncherBackgroundSet(int cid) {
        if (mService != null) {
            try {
                mService.actionLauncherBackgroundSet(cid);
            } catch(RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
    }

    /**
     * Gets maximum number of failed password attempts after which container is either wiped or
     * disabled.
     * @param cid Container ID
     * @return the maximum number of failed password attempts after which container is either wiped
     *      or disabled
     */
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

    /**
     * Sets maximum number of failed password attempts after which container is either wiped or
     * disabled.
     * @param cid Container ID
     * @param maximum The maximum number of failed password attempts after which container is
     *      either wiped or disabled
     * @return True on success
     */
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

    /**
     * Gets the action to perform when wrong password
     * is entered by the user {@link #getPasswordMaxAttempts()} times.
     * This action is either to disable or to wipe the container.
     * @param cid Container ID
     * @return The action to perform as string
     * @hide
     *
     */
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

    /**
     * Sets the action to perform after user enters the wrong container password
     * for more than the number of times specified by {@link #getPasswordMaxAttempts} policy.
     * The action is either to disable or to wipe the container.
     * @param cid Container ID
     * @param action The action to perform as string
     * @return True on success
     *
     */
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

    /**
     * Initializes the password change process.
     * Call this method whenever the container password need to be changed.
     * Mainly this should be called from onPasswordExpiring() callback of your
     * {@link android.app.admin.DeviceAdminReceiver} derived class.
     * @param cid Container ID
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
     * Finishes the password change process.
     * Call this method after the container password has been changed.
     * Mainly this should be called from onPasswordChanged() callback of your
     * {@link android.app.admin.DeviceAdminReceiver} derived class.
     * @param cid Container ID
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
     * @hide
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

    /** @hide */
    public int isContainerAccount(String accountName) {
        if (mService != null) {
            try {
                return mService.isContainerAccount(accountName);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return 0;
    }

    /**
     * Fetches the system applications whitelist.
     * @return A bundle with the names of  whitelisted system application
     *
     * <p><br>
     * Example of usage:
     *
     * <pre>
     *    ...
     *    Bundle systemWhitelistBundle = getSystemWhitelist();
     *
     *    {@code ArrayList<String> systemWhitelist = new ArrayList<String>();}
     *    for (String packageName : systemWhitelistBundle.keySet()) {
     *        systemWhitelist.add(packageName);
     *     }
     *    ...
     * </pre>
     */
    public Bundle getSystemWhitelist() {
        if (mService != null) {
            try {
                return mService.getSystemWhitelist();
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }

    /**
     * Gets a list of applications that can be removed from a container
     * @param cid Container ID
     * @return A list of container's removable applications
     */
    public List<ActivityInfo> getAvailableAppsForDeletion(int cid) {
        if (mService != null) {
            try {
                return mService.getAvailableAppsForDeletion(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return null;
    }

    /**
     * Triggers the container launcher installation for specified container.
     *
     * @param cid Container ID
     * @return True if container launcher installation was triggered
     */
    public boolean installContainerLauncher(int cid) {
        if (mService != null) {
            try {
                return mService.installContainerLauncher(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Checks if the container launcher is installed for specified container.
     *
     * @param cid Container ID
     * @return True if container launcher is installed
     */
    public boolean isContainerLauncherInstalled(int cid) {
        if (mService != null) {
            try {
                return mService.isContainerLauncherInstalled(cid);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
        return false;
    }

    /**
     * Reboots the device.
     * Should be called only in case ecryptfs failed to
     * unmount for the container.
     * Only container's MDM can reboot the device.
     * @param cid ID for container that failed to unmount.
     * @param reason Description of reboot reason.
     */
    public void rebootDevice(int cid, String reason) {
        if (mService != null) {
            try {
                mService.rebootDevice(cid, reason);
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with container manager service", e);
            }
        }
    }
}

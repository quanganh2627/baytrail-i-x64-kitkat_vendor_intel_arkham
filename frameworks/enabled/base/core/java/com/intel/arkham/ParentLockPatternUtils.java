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

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.IBinder;
import android.os.IUserManager;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.security.KeyStore;
import android.util.Log;
import android.util.Slog;
import android.widget.Toast;

import com.android.internal.R;
import com.android.internal.widget.ILockSettings;
import com.android.internal.widget.LockPatternView;
import com.android.internal.widget.LockPatternUtils;

import java.util.List;

/** @hide */
public abstract class ParentLockPatternUtils {

    private static final String TAG = "LockPatternUtils";
    // ARKHAM - 596, isContainerUserMode - setting false will show primary user's keyguard.
//    protected static volatile boolean isContainerUserMode = false;
    // ARKHAM - 596, sContainerUserId - is set by PhoneWindowManager.
//   protected static volatile int sContainerUserId = UserHandle.USER_NULL;

    protected abstract int getCurrentOrCallingUserId();

    protected abstract byte[] absPatternToHash(List<LockPatternView.Cell> pattern);

    public abstract byte[] passwordToHash(String password);

    protected abstract ILockSettings getLockSettings();

    public abstract boolean savedPatternExists();

    public abstract boolean savedPasswordExists();

    public abstract void clearLock(boolean isFallback);

    public abstract void reportFailedPasswordAttempt();

    public abstract void reportSuccessfulPasswordAttempt();

    private Context mContext;

    protected ParentLockPatternUtils (Context context) {
        mContext = context;
    }

    /**
     * ARKHAM-215: get container manager service
     */
    protected IContainerManager getContainerManager() {
        IContainerManager containerService = IContainerManager.Stub.asInterface(
                (IBinder) ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE));
        if (containerService == null) Log.e(TAG,
                "Failed to retrieve a ContainerManagerService instance.");
        return containerService;
    }

    /**
     * ARKHAM-777: wrapper for ContainerManagerService call
     */
    protected void mountContainerSystemData(int cid, byte[] hash) {
        try {
            IContainerManager containerService = getContainerManager();
            if (containerService != null) {
                containerService.mountContainerSystemData(cid, hash);
            }
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with Container Manager Service!");
        }
    }

    /**
     * ARKHAM-777: wrapper for ContainerManagerService call
     */
    protected void unmountContainerSystemData(int cid) {
        try {
            IContainerManager containerService = getContainerManager();
            if (containerService != null) {
                containerService.unmountContainerSystemData(cid);
            }
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with Container Manager Service!");
        }
    }

    /**
     * ARKHAM-777: wrapper for ContainerManagerService call
     */
    protected boolean isContainerSystemDataMounted() {
        try {
            IContainerManager containerService = getContainerManager();
            if (containerService != null) {
                return containerService.isContainerSystemDataMounted(getCurrentOrCallingUserId());
            }
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with Container Manager Service!");
        }
        return false;
    }

    /**
     * ARKHAM-215: wrapper for ContainerManagerService call
     * ARKHAM-596: Included @userId, Binder Identity will be set to SYSTEM_UID.
     */
    protected int markContainerOpen(byte[] hash, int userId) {
        int ret = ContainerConstants.NO_ERROR;
        try {
            IContainerManager containerService = getContainerManager();
            if (containerService != null) {
                // ARKHAM - 596, Including userId.
                ret = containerService.unlockContainer(hash, userId);
            }
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with Container Manager Service!");
            ret = ContainerConstants.ERROR_NO_SERVICE;
        }
        if (ret != ContainerConstants.NO_ERROR) {
            // Display the ContainerManager ErrorReport screen
            String message = "";
            switch (ret) {
            case ContainerConstants.ERROR_NO_SERVICE:
                message = mContext.getString(R.string.container_err_no_service);
                break;
            case ContainerConstants.ERROR_PERMISSION_DENIED:
                message = mContext.getString(R.string.container_err_permission_denied);
                break;
            case ContainerConstants.ERROR_CONTAINER_DISABLED:
                message = mContext.getString(R.string.container_err_disabled);
                break;
            case ContainerConstants.ERROR_COULD_NOT_MOUNT:
                message = mContext.getString(R.string.container_err_mount);
                break;
            default:
                message = mContext.getString(R.string.container_err_unknown);
            }
            Toast.makeText(mContext, message, Toast.LENGTH_LONG).show();
        }
        return ret;
    }

    protected long getLong(String secureSettingKey, long defaultValue, int userHandle)
            throws RemoteException {
        Log.e(TAG, "getLong:secureSettingKey " + secureSettingKey
                + "userHandle:" + Integer.toString(userHandle));
        if (LockPatternUtils.PASSWORD_TYPE_KEY.equals(secureSettingKey)) {
            Log.e(TAG, "Container getLong:secureSettingKey "
                    + Long.toString(getContainerPasswordType(defaultValue, userHandle)));
            return getContainerPasswordType(defaultValue, userHandle);
        } else {
            return getLockSettings().getLong(secureSettingKey, defaultValue, userHandle);
        }
    }

    /**
     * ARKHAM-215: wrapper for ContainerManagerService call
     *
     * ARKHAM - 271, Don't change the password if the container
     * service hasn't succesfully changed it
     */
    protected boolean changeContainerLockPassword(int cid, boolean isFallback, Object pwdObj,
            int quality, boolean isPattern) {
        IContainerManager containerService = getContainerManager();
        if(pwdObj != null && isContainerUser(cid)) {
            if (containerService == null) {
                Log.e(TAG, "Container service is null");
                return false;
            }
            try {
                int pwdType;
                String pwd;
                if(isPattern) {
                    pwd = LockPatternUtils.patternToString((List<LockPatternView.Cell>)pwdObj);
                    pwdType = DevicePolicyManager.PASSWORD_QUALITY_SOMETHING;
                } else {
                    pwd = (String) pwdObj;
                    pwdType = Math.max(quality, LockPatternUtils.computePasswordQuality(pwd));
                }
                byte[] hash = passwordToHash(pwd);
                if(!containerService.changePassword(cid, hash, pwdType)) {
                    String s = mContext.getResources().getString(R.string.change_password_failed);
                    Toast.makeText(mContext, s, Toast.LENGTH_SHORT).show();
                    Log.e(TAG, "Couldn't save lock password.");
                    return false;
                } else {
                    clearLock(isFallback);
                    if (!isPattern) {
                        KeyStore keyStore = KeyStore.getInstance();
                        if (keyStore == null) {
                            Log.e(TAG, "Failed to retrieve a KeyStore instance.");
                            return false;
                        }
                        keyStore.password(pwd);
                    }
                }
            } catch (RemoteException e) {
                Log.w(TAG, "Failed talking with Container Manager Service!");
                return false;
            }
        }

        return true;
    }

    /**
     * ARKHAM-777: wrapper for ContainerManagerService call
     */
    protected long getContainerPasswordType(long defaultValue, int containerId) {
    try {
             IContainerManager containerService = getContainerManager();
             if (containerService != null)
                 return containerService.getPasswordType(containerId);
         } catch (RemoteException e) {
             Log.w(TAG, "Failed talking with Container Manager Service!");
         }
        return defaultValue;
     }

    /**
     * ARKHAM-215: wrapper for UserManagerService call
     */
    protected boolean isContainerUser(int userId) {
        Log.w(TAG, "userId is " + Integer.toString(userId));
        IUserManager userManager = IUserManager.Stub.asInterface(ServiceManager.getService("user"));
        if (userManager == null) {
            Log.e(TAG, "Failed to retrieve a UserManager instance.");
            return false;
        }
        long ident = Binder.clearCallingIdentity();
        try {
            UserInfo userInfo = userManager.getUserInfo(userId);
            if (userInfo != null) {
                return userInfo.isContainer();
            }
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with User Manager Service!");
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
        return false;
    }

    // ARKHAM - 596. No permissions required, internal api.
    public void setContainerUserMode(int userId) {
	Slog.w(TAG, this.getClass().getName() + "userId is " + Integer.toString(userId)
                + ".  this is " + Integer.toHexString(System.identityHashCode(this)),
                (new RuntimeException("setContainerUserMode").fillInStackTrace()));

        try {
            IContainerManager containerService = getContainerManager();
            if (containerService != null) {
                containerService.setContainerUserMode();
                containerService.setsContainerUserId(userId);
            }
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with Container Manager Service!");
        }

    }

    protected int getsContainerUserId() {
        int sContainerUserId = UserHandle.USER_NULL;
	try {
            IContainerManager containerService = getContainerManager();
            if (containerService != null) {
		sContainerUserId = containerService.getsContainerUserId();
            }
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with Container Manager Service!");
        }
	return sContainerUserId;
    }

    public boolean isContainerUserMode() {
        boolean isContainerUserMode = false;

        try {
            IContainerManager containerService = getContainerManager();
            if (containerService != null) {
                isContainerUserMode = containerService.isContainerUserMode();
            }
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with Container Manager Service!");
        }

	Slog.w(TAG, this.getClass().getName() + "ContainerUserMode is "
                + Boolean.toString(isContainerUserMode) + ". this is "
                + Integer.toHexString(System.identityHashCode(this)),
                (new RuntimeException("isContainerUserMode").fillInStackTrace()));

        return isContainerUserMode;
    }

    public void resetContainerUserMode() {
	Slog.w(TAG, this.getClass().getName() + "Reset ContainerUserMode" + ". this is "
                + Integer.toHexString(System.identityHashCode(this)),
                (new RuntimeException("isContainerUserMode").fillInStackTrace()));
        try {
            IContainerManager containerService = getContainerManager();
            if (containerService != null) {
                containerService.resetContainerUserMode();
            }
        } catch (RemoteException e) {
            Log.w(TAG, "Failed talking with Container Manager Service!");
        }
    }
    // ARKHAM - 596 Ends.

    /**
     * call only if userId is containerUser.
     */
    public boolean checkPattern(List<LockPatternView.Cell> pattern, int userId) {
        byte[] containerPassword = passwordToHash(LockPatternUtils.patternToString(pattern));
        boolean matched = false, isContainerMounted = false;
        try {
            isContainerMounted = isContainerSystemDataMounted();
            if (!isContainerMounted) {
                mountContainerSystemData(userId, containerPassword);
                // for users this check is done earlier but we bypass it
                // since ecryptfs is not mounted
                if (!savedPatternExists()) {
                    return false;
                }
            }
            matched = getLockSettings().checkPattern(
                    LockPatternUtils.patternToString(pattern), userId);
            if (matched) {
                markContainerOpen(containerPassword, userId);
                unlockKeystore(LockPatternUtils.patternToString(pattern));
            }
            return matched;
        } catch (RemoteException re) {
            return false;
        } finally {
            if (!matched && !isContainerMounted)
                unmountContainerSystemData(userId);
        }
    }

    /**
     * call only if the userId is ContainerUser.
     */
    public boolean checkPassword(String password, int userId) {
        byte[] containerPassword = passwordToHash(password);
        boolean matched = false, isContainerMounted = false;
        try {
            isContainerMounted = isContainerSystemDataMounted();
            if (!isContainerMounted) {
                mountContainerSystemData(userId, containerPassword);
                // for users this check is done earlier but we bypass it
                // since ecryptfs is not mounted
                if (!savedPasswordExists())
                    return false;
            }

            matched = getLockSettings().checkPassword(password, userId);
            if (matched) {
                markContainerOpen(containerPassword, userId);
                unlockKeystore(password);
            }
            return matched;
        } catch (RemoteException re) {
            return false;
        } finally {
            if (!matched && !isContainerMounted)
                unmountContainerSystemData(userId);
        }
    }

    private void unlockKeystore(String password) {
        long bToken = Binder.clearCallingIdentity();
        try {
            IContainerManager cm = getContainerManager();
            if (cm == null) return;
            Intent intent = new Intent(ContainerConstants.ACTION_UNLOCK_CONTAINER_KEYSTORE);
            intent.setPackage(cm.getContainerMdmPackageName());
            intent.putExtra(ContainerConstants.EXTRA_KEYSTORE_PASSWORD, password);
            mContext.sendBroadcastAsUser(intent, new UserHandle(getsContainerUserId()));
        } catch (RemoteException e) {
            e.printStackTrace();
        } finally {
            Binder.restoreCallingIdentity(bToken);
        }
    }
}

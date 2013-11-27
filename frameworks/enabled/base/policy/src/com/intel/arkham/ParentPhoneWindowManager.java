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
import android.os.Handler;
import android.os.IBinder;
import android.os.PowerManager;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.util.Log;

import com.android.internal.widget.LockPatternUtils;
import com.android.internal.policy.impl.keyguard.KeyguardServiceDelegate;

import java.util.HashMap;
import java.util.Map;

public abstract class ParentPhoneWindowManager {

    static final String TAG = "PhoneWindowManager";

    /* ARKHAM-424: START - Set the timeout password period based on device activity
     * keep the Runnable objects for closing containers locally, so we can repost them
     * when we have user activity.
     */
    protected static class ContainerCloseAction {
        public Runnable closeAction;
        public long timeout;
        public int timeoutType;

        public ContainerCloseAction(Runnable closeAction, long timeout, int type) {
            this.closeAction = closeAction;
            this.timeout = Math.abs(timeout);
            this.timeoutType = type;
        }
    }

    protected HashMap<Integer, ContainerCloseAction> mContainerCloseActions
            = new HashMap<Integer, ContainerCloseAction>();
    // AKHAM-424 END

    // ARKHAM - 596, need to set / get current user.
    protected LockPatternUtils mLockPatternUtils;

    protected abstract Handler getHandler();

    protected abstract KeyguardServiceDelegate getKeyguardServiceDelegate();

    public void init(Context context) {
        // ARKHAM - 596.
        mLockPatternUtils = new LockPatternUtils(context);
    }

    public void screenTurnedOff(int why) {
        // ARKHAM-596 Starts.
        try {
            // reset lock pattern utils, so that primary user keyguard comes up.
            mLockPatternUtils.resetContainerUserMode();
            /* ARKHAM-1278 Close all containers when the power button is pressed.
             * The constant name "GO_TO_SLEEP_REASON_TIMEOUT" is misleading. This constant actually
             * corresponds to the action of the user locking the device by pressing the power
             * button.
             */
            if (why == PowerManager.GO_TO_SLEEP_REASON_TIMEOUT) {
                removeAllContainerCallbacks();
                IContainerManager cm = getContainerManager();
                if (cm == null) return;
                cm.lockContainerNow(UserHandle.USER_ALL);
            }
        } catch (RemoteException e) {
            // Should not happen.
        }
        // ARKHAM-596 Ends.
    }

    public void userActivity() {
        /* ARKHAM-1278 Interacting with the keyguard shouldn't be considered "user activity". */
        if (getKeyguardServiceDelegate().isShowing()) return;
        /* ARKHAM-424: START - Set the timeout password period based on device activity
         * On user activity, reset all the active container close Runnable objects.
         */
        synchronized (mContainerCloseActions) {
            for (Map.Entry<Integer,ContainerCloseAction>entry : mContainerCloseActions.entrySet()) {
                ContainerCloseAction action = entry.getValue();
                int cid = entry.getKey();
                // If this container timeout type is based on container activity, check the current
                // running activity
                if (action.timeoutType == ContainerConstants.TIMEOUT_TYPE_CONTAINER_ACTIVITY) {
                    // check for current activity; if not container activity, continue
                    try {
                        IContainerManager cm = getContainerManager();
                        if (cm == null) return;
                        if (!cm.isTopRunningActivityInContainer(cid)) {
                            continue;
                        }
                    } catch (RemoteException ex) {}
                }
                getHandler().removeCallbacks(action.closeAction);
                getHandler().postDelayed(action.closeAction, action.timeout);
            }
        }
        // ARKHAM-424: END
    }

    /**
     * ARKHAM-596, used when screen turned off.
     */
    private void removeAllContainerCallbacks() {
        synchronized (mContainerCloseActions) {
            for (Map.Entry<Integer, ContainerCloseAction> entry
                    : mContainerCloseActions.entrySet()) {
                ContainerCloseAction action = entry.getValue();
                getHandler().removeCallbacks(action.closeAction);
            }
        }
    }

    /**
     * ARKHAM-596, Runnable posted for container timeout.
     */
    class CloseAction implements Runnable {

        int cid;

        public CloseAction(int cid){
            this.cid = cid;
        }

        public void run () {
            try {
                IContainerManager cm = getContainerManager();
                if (cm == null) return;
                cm.lockContainerNow(cid);
                removeContainerCloseAction(cid);
                /* ARKHAM-1278 Don't override the primary user's keyguard. */
                KeyguardServiceDelegate ksd = getKeyguardServiceDelegate();
                if (ksd != null && cm.isTopRunningActivityInContainer(cid) &&
                        !(ksd.isShowing() && !mLockPatternUtils.isContainerUserMode())) {
                /* End ARKHAM-1278. */
                    mLockPatternUtils.setContainerUserMode(cid);
                    ksd.doKeyguardTimeout(null);
                }
            } catch (RemoteException e) {
                // Should not happen.
            }
        }
    }
    // ARKHAM-596.
    private IContainerManager mContainerManager;
    private IContainerManager getContainerManager() {
        if (mContainerManager == null) {
            IBinder b = ServiceManager.getService(ContainerConstants.CONTAINER_MANAGER_SERVICE);
            mContainerManager = IContainerManager.Stub.asInterface(b);
        }
        if (mContainerManager == null)
            Log.e(TAG, "Failed to retrieve a ContainerManagerService instance.");
        return mContainerManager;
    }
    // ARKHAM-596 Ends.

    /* ARKHAM-424: START - Set the timeout password period based on device activity
     * Public functions to be used by ContainerManagerService to post/remove Runnable
     * objects to be called after a timeout period, so that we can deactivate containers.
     */
    public void postContainerCloseAction(int cid, long timeout, int type) {
        // make sure there isn't another close action already set for this container
        removeContainerCloseAction(cid);
        if (timeout <= 0)
            return;
        synchronized (mContainerCloseActions) {
            CloseAction closeAction = new CloseAction(cid);
            ContainerCloseAction action = new ContainerCloseAction(closeAction, timeout, type);
            mContainerCloseActions.put(cid, action);
            getHandler().postDelayed(closeAction, action.timeout);
        }
    }

    public boolean removeContainerCloseAction(int cid) {
        synchronized (mContainerCloseActions) {
            if (mContainerCloseActions.containsKey(cid)) {
                ContainerCloseAction action = mContainerCloseActions.get(cid);
                if (action != null) {
                    getHandler().removeCallbacks(action.closeAction);
                }
                mContainerCloseActions.remove(cid);
                return true;
            }
            return false;
        }
    }
    // ARKHAM-424: END

    /**
     * ARKHAM-596, called from Container Manager Service when Launcher / DPM calls lockNow.
     */
    public void lockContainerNow(int cid, boolean isContainerOpen) {
        /* ARKHAM-1351 If the container has just been disabled, don't show the keyguard. */
        try {
            IContainerManager cm = getContainerManager();
            if (cm != null && cm.isContainerDisabled(cid)) return;
        } catch (RemoteException e) {
            // Should not happen.
        }
        /* End ARKHAM-1351 */
        synchronized (mContainerCloseActions) {
            if (!isContainerOpen) {
                ContainerCloseAction action = mContainerCloseActions.get(cid);
                if (action == null) {
                    CloseAction runnable = new CloseAction(cid);
                    action = new ContainerCloseAction(runnable, 0, 0);
                }
                mContainerCloseActions.put(cid, action);
                getHandler().post(action.closeAction);
            } else {
                mLockPatternUtils.setContainerUserMode(cid);
                getKeyguardServiceDelegate().doKeyguardTimeout(null);
            }
        }
    }

    protected void doScreenLockTimeout() {
        // ARKHAM-596, unset container user mode so that normal keyguard comes up.
        mLockPatternUtils.resetContainerUserMode();
    }
}

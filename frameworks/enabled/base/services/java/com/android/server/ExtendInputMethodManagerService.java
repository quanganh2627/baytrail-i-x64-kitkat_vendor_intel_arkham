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

package com.android.server;

import java.util.List;

import com.android.internal.inputmethod.InputMethodUtils;
import com.android.internal.view.IInputMethod;
import com.android.internal.widget.LockPatternUtils;
import com.android.server.InputMethodManagerService;
import com.android.server.wm.WindowManagerService;
import com.android.server.am.ActivityManagerService;
import com.android.server.am.ExtendActivityManagerService;
import com.android.server.am.ExtendActivityManagerService.ForegroundUserObserver;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.IBinder;
import android.os.ResultReceiver;
import android.os.UserHandle;
import android.os.UserManager;
import android.text.style.SuggestionSpan;
import android.util.Pair;
import android.util.Slog;
import android.view.InputChannel;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodSubtype;

import com.android.internal.view.IInputContext;
import com.android.internal.view.IInputMethodClient;
import com.android.internal.view.IInputMethodSession;
import com.android.internal.view.InputBindResult;
import com.android.internal.widget.LockPatternUtils;
import com.android.server.am.ActivityManagerService;
import com.android.server.am.ExtendActivityManagerService;
import com.android.server.am.ExtendActivityManagerService.ForegroundUserObserver;
import com.android.server.wm.WindowManagerService;

/**
 * This class provides a system service that manages input methods.
 */
/** {@hide} */

public class ExtendInputMethodManagerService extends InputMethodManagerService {
    static final boolean DEBUG = false;
    static final String TAG = "ExtendInputMethodManagerService";
    private boolean isResetPending = false;
    private LockPatternUtils mlpu;

    public ExtendInputMethodManagerService(Context context, WindowManagerService windowManager) {
        super(context, windowManager);
        // ARKHAM - 198, register foreground user switch observer.
        ((ExtendActivityManagerService) ActivityManagerService.self())
                .registerForegroundUserObserver(new ForegroundUserObserver() {
                    @Override
                    public void userComingForeground(int userId) {
                        synchronized (mMethodMap) {
                            switchUserLocked(userId);
                        }
                    }
                });
        // ARKHAM Changes End.
        mlpu = new LockPatternUtils(mContext);
    }

    protected void checkAndShowSystemImeForContainer() {
        if (mlpu.isContainerUserMode() && isScreenLocked()) {
            InputMethodInfo imi = InputMethodUtils.getMostApplicableDefaultIME(mSettings
                    .getEnabledInputMethodListLocked());
            if (imi == null) {
                Slog.e(TAG, "Failed to retrieve default IME.");
                return;
            }
            String id = imi.getId();
            setInputMethodLocked(id, mSettings.getSelectedInputMethodSubtypeId(id));
            isResetPending = true;
            // resetDefaultImeLocked(mContext);
            Slog.i(TAG, "!@reset Default Ime Locked");
        }
        restoreInputMethod();
    }

    protected boolean calledFromValidUser() {
        final int uid = Binder.getCallingUid();
        final int userId = UserHandle.getUserId(uid);

        // ARKHAM-115 Allow applications started from container to use the
        // input service if the current user is the owner of that container,
        // because by default Android perceive the applications started from
        // containers as background users and implicitly they are denied from
        // using the input.
        final long ident = Binder.clearCallingIdentity();
        try {
            UserManager um = (UserManager) mContext.getSystemService(Context.USER_SERVICE);
            UserInfo userInfo = null;

            if (um != null)
                userInfo = um.getUserInfo(userId);
            if (userInfo != null && userInfo.isContainer()
                    && mSettings.getCurrentUserId() == userInfo.containerOwner) {
                return true;
            }
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
        // ARKHAM-115 - end changes

        return super.calledFromValidUser();
    }

    private void restoreInputMethod() {
        if (isResetPending) {
            final Pair<String, String> lastIme = mSettings.getLastInputMethodAndSubtypeLocked();
            final InputMethodInfo lastImi;
            if (lastIme != null) {
                lastImi = mMethodMap.get(lastIme.first);
                if (lastImi != null) {
                    String id = lastImi.getId();
                    isResetPending = false;
                    setInputMethodLocked(id, mSettings.getSelectedInputMethodSubtypeId(id));
                }
            }
        }
    }

    protected void switchUserLocked(int newUserId) {
        restoreInputMethod();
        super.switchUserLocked(newUserId);
    }

    @Override
    public List<InputMethodInfo> getEnabledInputMethodList() {
        synchronized (ActivityManagerService.self()) {
            return super.getEnabledInputMethodList();
        }
    }

    @Override
    public List<InputMethodInfo> getInputMethodList() {
        synchronized (ActivityManagerService.self()) {
            return super.getInputMethodList();
        }
    }

    @Override
    public List<InputMethodSubtype> getEnabledInputMethodSubtypeList(String imiId,
            boolean allowsImplicitlySelectedSubtypes) {
        synchronized (ActivityManagerService.self()) {
            return super.getEnabledInputMethodSubtypeList(imiId, allowsImplicitlySelectedSubtypes);
        }
    }

    @Override
    public InputMethodSubtype getLastInputMethodSubtype() {
        synchronized (ActivityManagerService.self()) {
            return super.getLastInputMethodSubtype();
        }
    }

    @Override
    public List getShortcutInputMethodsAndSubtypes() {
        synchronized (ActivityManagerService.self()) {
            return super.getShortcutInputMethodsAndSubtypes();
        }
    }

    @Override
    public void addClient(IInputMethodClient client, IInputContext inputContext, int uid, int pid) {
        synchronized (ActivityManagerService.self()) {
            super.addClient(client, inputContext, uid, pid);
        }
    }

    @Override
    public void removeClient(IInputMethodClient client) {
        synchronized (ActivityManagerService.self()) {
            super.removeClient(client);
        }
    }

    @Override
    public InputBindResult startInput(IInputMethodClient client, IInputContext inputContext,
            EditorInfo attribute, int controlFlags) {
        synchronized (ActivityManagerService.self()) {
            return super.startInput(client, inputContext, attribute, controlFlags);
        }
    }

    @Override
    public void finishInput(IInputMethodClient client) {
        synchronized (ActivityManagerService.self()) {
            super.finishInput(client);
        }
    }

    @Override
    public boolean showSoftInput(IInputMethodClient client, int flags,
            ResultReceiver resultReceiver) {
        synchronized (ActivityManagerService.self()) {
            return super.showSoftInput(client, flags, resultReceiver);
        }
    }

    @Override
    public boolean hideSoftInput(IInputMethodClient client, int flags,
            ResultReceiver resultReceiver) {
        synchronized (ActivityManagerService.self()) {
            return super.hideSoftInput(client, flags, resultReceiver);
        }
    }

    @Override
    public InputBindResult windowGainedFocus(IInputMethodClient client, IBinder windowToken,
            int controlFlags, int softInputMode, int windowFlags, EditorInfo attribute,
            IInputContext inputContext) {
        synchronized (ActivityManagerService.self()) {
            return super.windowGainedFocus(client, windowToken, controlFlags, softInputMode,
                    windowFlags, attribute, inputContext);
        }
    }

    @Override
    public void showInputMethodPickerFromClient(IInputMethodClient client) {
        synchronized (ActivityManagerService.self()) {
            super.showInputMethodPickerFromClient(client);
        }
    }

    @Override
    public void showInputMethodAndSubtypeEnablerFromClient(IInputMethodClient client,
            String inputMethodId) {
        synchronized (ActivityManagerService.self()) {
            super.showInputMethodAndSubtypeEnablerFromClient(client, inputMethodId);
        }
    }

    @Override
    public void setInputMethod(IBinder token, String id) {
        synchronized (ActivityManagerService.self()) {
            super.setInputMethod(token, id);
        }
    }

    @Override
    public void setInputMethodAndSubtype(IBinder token, String id, InputMethodSubtype subtype) {
        synchronized (ActivityManagerService.self()) {
            super.setInputMethodAndSubtype(token, id, subtype);
        }
    }

    @Override
    public void hideMySoftInput(IBinder token, int flags) {
        synchronized (ActivityManagerService.self()) {
            super.hideMySoftInput(token, flags);
        }
    }

    @Override
    public void showMySoftInput(IBinder token, int flags) {
        synchronized (ActivityManagerService.self()) {
            super.showMySoftInput(token, flags);
        }
    }

    @Override
    public void updateStatusIcon(IBinder token, String packageName, int iconId) {
        synchronized (ActivityManagerService.self()) {
            super.updateStatusIcon(token, packageName, iconId);
        }
    }

    @Override
    public void setImeWindowStatus(IBinder token, int vis, int backDisposition) {
        synchronized (ActivityManagerService.self()) {
            super.setImeWindowStatus(token, vis, backDisposition);
        }
    }

    @Override
    public void registerSuggestionSpansForNotification(SuggestionSpan[] spans) {
        synchronized (ActivityManagerService.self()) {
            super.registerSuggestionSpansForNotification(spans);
        }
    }

    @Override
    public boolean notifySuggestionPicked(SuggestionSpan span, String originalString, int index) {
        synchronized (ActivityManagerService.self()) {
            return super.notifySuggestionPicked(span, originalString, index);
        }
    }

    @Override
    public InputMethodSubtype getCurrentInputMethodSubtype() {
        synchronized (ActivityManagerService.self()) {
            return super.getCurrentInputMethodSubtype();
        }
    }

    @Override
    public boolean setCurrentInputMethodSubtype(InputMethodSubtype subtype) {
        synchronized (ActivityManagerService.self()) {
            return super.setCurrentInputMethodSubtype(subtype);
        }
    }

    @Override
    public boolean switchToLastInputMethod(IBinder token) {
        synchronized (ActivityManagerService.self()) {
            return super.switchToLastInputMethod(token);
        }
    }

    @Override
    public boolean switchToNextInputMethod(IBinder token, boolean onlyCurrentIme) {
        synchronized (ActivityManagerService.self()) {
            return super.switchToNextInputMethod(token, onlyCurrentIme);
        }
    }

    @Override
    public boolean setInputMethodEnabled(String id, boolean enabled) {
        synchronized (ActivityManagerService.self()) {
            return super.setInputMethodEnabled(id, enabled);
        }
    }

    @Override
    public void setAdditionalInputMethodSubtypes(String imiId, InputMethodSubtype[] subtypes) {
        synchronized (ActivityManagerService.self()) {
            super.setAdditionalInputMethodSubtypes(imiId, subtypes);
        }
    }

    @Override
    public void onServiceDisconnected(ComponentName name) {
        synchronized (ActivityManagerService.self()) {
            super.onServiceDisconnected(name);
        }
    }

    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        synchronized (ActivityManagerService.self()) {
            super.onServiceConnected(name, service);
        }
    }

    @Override
    void onSessionCreated(IInputMethod method, IInputMethodSession session, InputChannel channel) {
        synchronized (ActivityManagerService.self()) {
            super.onSessionCreated(method, session, channel);
        }
    }

    @Override
    void hideInputMethodMenu() {
        synchronized (ActivityManagerService.self()) {
            super.hideInputMethodMenu();
        }
    }
}

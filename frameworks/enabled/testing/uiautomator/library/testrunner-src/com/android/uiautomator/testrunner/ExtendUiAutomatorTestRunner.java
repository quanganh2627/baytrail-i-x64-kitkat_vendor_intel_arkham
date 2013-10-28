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

package com.android.uiautomator.testrunner;

import android.app.UiAutomation;

import com.android.uiautomator.core.ShellUiAutomatorBridge;
import com.android.uiautomator.core.UiAutomationShellWrapper;

/** @hide */
public class ExtendUiAutomatorTestRunner extends UiAutomatorTestRunner {
    @Override
    protected UiAutomationShellWrapper rebuildAutomationIfNeeded(
            UiAutomationShellWrapper automationWrapper) {
        UiAutomation uiAutomation = automationWrapper.getUiAutomation();
        if (!uiAutomation.isConnectedLocked()) {
            automationWrapper = new UiAutomationShellWrapper();
            automationWrapper.connect();
            automationWrapper.setRunAsMonkey(mMonkey);

            mUiDevice.initialize(new ShellUiAutomatorBridge(automationWrapper.getUiAutomation()));
        }
        return automationWrapper;
    }
}
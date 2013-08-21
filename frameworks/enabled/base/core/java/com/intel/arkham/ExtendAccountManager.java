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

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.IAccountManager;
import android.content.Context;
import android.os.Handler;

import com.intel.arkham.ContainerConstants;

public class ExtendAccountManager extends AccountManager {

    public ExtendAccountManager(Context context, IAccountManager service) {
        super(context, service);
    }

    public ExtendAccountManager(Context context, IAccountManager service, Handler handler) {
        super(context, service, handler);
    }

    @Override
    protected Account[] getContainerAccounts() {
        return getAccountsByType(ContainerConstants.ACCOUNT_TYPE_CONTAINER);
    }
}
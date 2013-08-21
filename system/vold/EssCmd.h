/*
 * Copyright (C) 2013 Intel Corporation, All Rights Reserved
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


/**
 * ARKHAM-30: Encrypt container application data
 * ARKHAM-952: Refactor arkham changes in system/vold
 * This file is used for VOLD container encryption commands.
 */

#ifndef _ESSCMD_H__
#define _ESSCMD_H__

#include "VoldCommand.h"
#include "ess.h"

class EssCmd : public VoldCommand {
public:
    EssCmd();
    virtual ~EssCmd() {}
    int runCommand(SocketClient *c, int argc, char ** argv);

private:
    /**
     * ARKHAM-30: Encrypt container application data
     * Add a specific set of commands to handle container encryption
     * and corresponding classes needed as parameters.
     */
    class EssKey {
    private:
        uint8_t mKey[ESS_KEY_LEN];
        uint8_t mSalt[ESS_SALT_LEN];
    public:
        const void* getKey(void) const;
        const void* getSalt(void) const;
        int setKey(const void * const data);
        int setSalt(const void * const data);
        int setKeyFromHex(const char * const hex);
        int setSaltFromHex(const char * const hex);
        void keyToHex(char * const str);
        void saltToHex(char * const str);
        size_t keySize(void) const;
        size_t saltSize(void) const;
    };

    class EssPwd {
    private:
        uint8_t mPwd[ESS_MAX_PWD_LEN];
        size_t mSize;
    public:
        const void* get(void) const;
        int setFromHex(const char * const hex);
        void toHex(char * const str);
        size_t size(void) const;
    };

    int createEss(int cid, EssPwd * const pwd, EssKey * const key);
    int mountEss(int cid, const char * const path, EssPwd * const pwd, EssKey * const key,
                 int user_id, int group_id);
    int unmountEss(const char * const path);
    int unmountAllEss(void);
    int changePasswordEss(int cid, EssPwd * const oldPwd, EssPwd * const newPwd,
                          EssKey * const key);
    int deleteEss(int cid);
    int enableEss(int cid);
    int disableEss(int cid);
};

#endif

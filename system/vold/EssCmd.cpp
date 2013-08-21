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

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#define LOG_TAG "VoldEssCmdListener"
#include <cutils/log.h>

#include <private/android_filesystem_config.h>

#include "CommandListener.h"
#include "ResponseCode.h"
#include "EssCmd.h"

/* Constants for argv patameters */
#define ESS_CMD 1
#define ESS_CREATE_CID 2
#define ESS_CREATE_PASSWD 3
#define ESS_MOUNT_CID 2
#define ESS_MOUNT_PATH 3
#define ESS_MOUNT_PASSWD 4
#define ESS_MOUNT_KEY 5
#define ESS_MOUNT_SALT 6
#define ESS_MOUNT_UID 7
#define ESS_MOUNT_CGID 8
#define ESS_UNMOUNT_PATH 2
#define ESS_CHANGEPW_CID 2
#define ESS_CHANGEPW_OLDPASS 3
#define ESS_CHANGEPW_NEWPASS 4
#define ESS_CHANGEPW_KEY 5
#define ESS_CHANGEPW_SALT 6
#define ESS_DELETE_CID 2
#define ESS_ENABLE_CID 2
#define ESS_DISABLE_CID 2

/* hex size for an array = double the size
 * (each value is stored in 2 hex characters) + 1 (\0) */
#define HEX_SIZE(value) ((value) * 2 + 1)

/**
 * ARKHAM-30: Encrypt container application data
 * Add a specific set of commands to handle container encryption.
 */
EssCmd::EssCmd() :
    VoldCommand("ess") {
}

/**
 * ARKHAM-30: Encrypt container application data
 * Add a specific set of commands to handle container encryption:
 */
int EssCmd::runCommand(SocketClient *cli, int argc, char **argv) {

    if ((cli->getUid() != AID_ROOT) && (cli->getUid() != AID_SYSTEM)) {
        cli->sendMsg(ResponseCode::CommandNoPermission, "No permission to run ess commands", false);
        return 0;
    }

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing Argument", false);
        return 0;
    }

    EssKey key;
    EssPwd pwd, oldPwd, newPwd;
    char hexKey[HEX_SIZE(key.keySize())];
    char hexSalt[HEX_SIZE(key.saltSize())];
    int cid = -1, uid = -1, cgid = -1;
    char *path = NULL;
    struct stat path_stat;
    int rc = 0;

    if (!strcmp(argv[ESS_CMD], "create")) {
        if (argc != 4) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: ess create <cid> <passwd>", false);
            return 0;
        }
        CommandListener::dumpArgs(3, argv, -1);
        cid = atoi(argv[ESS_CREATE_CID]);
        if (cid <= 0) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid cid", false);
            return 0;
        }
        rc = pwd.setFromHex(argv[ESS_CREATE_PASSWD]);
        if (rc) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid password", false);
            return 0;
        }
        rc = createEss(cid, &pwd, &key);
        if (rc) {
            rc = ResponseCode::convertFromErrno();
            cli->sendMsg(rc, "ess create operation failed", true);
            return 0;
        }

        key.keyToHex(hexKey);
        cli->sendMsg(ResponseCode::EssKeyResult, hexKey, false);
        key.saltToHex(hexSalt);
        cli->sendMsg(ResponseCode::EssKeyResult, hexSalt, false);
    } else if (!strcmp(argv[ESS_CMD], "mount")) {
        if (argc != 9) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: ess mount <cid> <path> <passwd> <32 digit hexadecimal key> "
                         "<32 digit hexadecimal salt> <user id> <container group>", false);
            return 0;
        }
        CommandListener::dumpArgs(4, argv, -1);
        cid = atoi(argv[ESS_MOUNT_CID]);
        if (cid <= 0) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid cid", false);
            return 0;
        }
        rc = pwd.setFromHex(argv[ESS_MOUNT_PASSWD]);
        if (rc) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid password", false);
            return 0;
        }
        rc = key.setKeyFromHex(argv[ESS_MOUNT_KEY]);
        if (rc) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid key", false);
            return 0;
        }
        rc = key.setSaltFromHex(argv[ESS_MOUNT_SALT]);
        if (rc) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid salt", false);
            return 0;
        }
        uid = atoi(argv[ESS_MOUNT_UID]);
        if (uid < 0) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid user id", false);
            return 0;
        }
        cgid = atoi(argv[ESS_MOUNT_CGID]);
        if (cgid < AID_CONT_FIRST || cgid >  AID_CONT_LAST) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid container group", false);
            return 0;
        }
        rc = mountEss(cid, argv[ESS_MOUNT_PATH], &pwd, &key, uid, cgid);
        if (rc) {
            rc = ResponseCode::convertFromErrno();
            cli->sendMsg(rc, "ess mount operation failed", true);
            return 0;
        }
    } else if (!strcmp(argv[ESS_CMD], "unmount")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: ess unmount <path>", false);
            return 0;
        }
        CommandListener::dumpArgs(argc, argv, -1);
        path = argv[ESS_UNMOUNT_PATH];
        rc = stat(path, &path_stat);
        if (rc) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid path", false);
            return 0;
        }
        rc = unmountEss(argv[ESS_UNMOUNT_PATH]);
        if (rc) {
            rc = ResponseCode::convertFromErrno();
            cli->sendMsg(rc, "ess unmount operation failed", true);
            return 0;
        }
    } else if (!strcmp(argv[ESS_CMD], "unmountall")) {
        if (argc != 2) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: ess unmountall", false);
            return 0;
        }
        CommandListener::dumpArgs(argc, argv, -1);
        rc = unmountAllEss();
        if (rc) {
            rc = ResponseCode::convertFromErrno();
            cli->sendMsg(rc, "ess unmountall operation failed", true);
            return 0;
        }
    } else if (!strcmp(argv[ESS_CMD], "changepw")) {
        if (argc != 7) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: ess changepw <cid> <oldpass> <newpass> "
                         "<32 digit hexadecimal key> <32 digit hexadecimal salt>", false);
            return 0;
        }
        CommandListener::dumpArgs(3, argv, -1);
        cid = atoi(argv[ESS_CHANGEPW_CID]);
        if (cid <= 0) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid cid", false);
            return 0;
        }
        rc = oldPwd.setFromHex(argv[ESS_CHANGEPW_OLDPASS]);
        if (rc) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid password", false);
            return 0;
        }
        rc = newPwd.setFromHex(argv[ESS_CHANGEPW_NEWPASS]);
        if (rc) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid password", false);
            return 0;
        }
        rc = key.setKeyFromHex(argv[ESS_CHANGEPW_KEY]);
        if (rc) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid key", false);
            return 0;
        }
        rc = key.setSaltFromHex(argv[ESS_CHANGEPW_SALT]);
        if (rc) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid salt", false);
            return 0;
        }
        rc = changePasswordEss(cid, &oldPwd, &newPwd, &key);
        if (rc) {
            rc = ResponseCode::convertFromErrno();
            cli->sendMsg(rc, "ess changepw operation failed", true);
            return 0;
        }

        key.keyToHex(hexKey);
        cli->sendMsg(ResponseCode::EssKeyResult, hexKey, false);
    } else if (!strcmp(argv[ESS_CMD], "delete")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: ess delete <cid>", false);
            return 0;
        }
        CommandListener::dumpArgs(argc, argv, -1);
        cid = atoi(argv[ESS_DELETE_CID]);
        if (cid <= 0) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid cid", false);
            return 0;
        }
        rc = deleteEss(cid);
        if (rc) {
            rc = ResponseCode::convertFromErrno();
            cli->sendMsg(rc, "ess delete operation failed", true);
            return 0;
        }
    } else if (!strcmp(argv[ESS_CMD], "enable")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: ess enable <cid>", false);
            return 0;
        }
        CommandListener::dumpArgs(argc, argv, -1);
        cid = atoi(argv[ESS_ENABLE_CID]);
        if (cid <= 0) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid cid", false);
            return 0;
        }
        rc = enableEss(cid);
        if (rc) {
            rc = ResponseCode::convertFromErrno();
            cli->sendMsg(rc, "ess enable operation failed", true);
            return 0;
        }
    } else if (!strcmp(argv[ESS_CMD], "disable")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: ess disable <cid>", false);
            return 0;
        }
        CommandListener::dumpArgs(argc, argv, -1);
        cid = atoi(argv[ESS_DISABLE_CID]);
        if (cid <= 0) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "invalid cid", false);
            return 0;
        }
        rc = disableEss(cid);
        if (rc) {
            rc = ResponseCode::convertFromErrno();
            cli->sendMsg(rc, "ess disable operation failed", true);
            return 0;
        }
    } else {
        CommandListener::dumpArgs(argc, argv, -1);
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown ess cmd", false);
        return 0;
    }

    cli->sendMsg(ResponseCode::CommandOkay, "ess operation succeeded", false);
    return 0;
}

/**
 * ARKHAM-30: Encrypt container application data
 * Implement classes need as command parameters for
 * container encryption commands.
 */

const void* EssCmd::EssKey::getKey(void) const
{
    return mKey;
}

const void* EssCmd::EssKey::getSalt(void) const
{
    return mSalt;
}

int EssCmd::EssKey::setKey(const void * const data)
{
    if (data == NULL)
        return -1;
    memcpy(mKey, data, sizeof(mKey));
    return 0;
}

int EssCmd::EssKey::setSalt(const void * const data)
{
    if (data == NULL)
        return -1;
    memcpy(mSalt, data, sizeof(mSalt));
    return 0;
}

int EssCmd::EssKey::setKeyFromHex(const char * const hex)
{
    if (hex == NULL)
        return -1;
    /* key should have 32 hexadecimal digits */
    if (strlen(hex) != 2 * keySize())
        return -1;
    return from_hex(hex, mKey, sizeof(mKey));
}

int EssCmd::EssKey::setSaltFromHex(const char * const hex)
{
    if (hex == NULL)
        return -1;
    /* salt should have 32 hexadecimal digits */
    if (strlen(hex) != 2 * saltSize())
        return -1;
    return from_hex(hex, mSalt, sizeof(mSalt));
}

void EssCmd::EssKey::keyToHex(char *const str)
{
    to_hex(mKey, str, keySize());
}

void EssCmd::EssKey::saltToHex(char * const str)
{
    to_hex(mSalt, str, saltSize());
}

size_t EssCmd::EssKey::keySize(void) const
{
    return sizeof(mKey);
}

size_t EssCmd::EssKey::saltSize(void) const
{
    return sizeof(mSalt);
}


const void* EssCmd::EssPwd::get(void) const
{
    return mPwd;
}

int EssCmd::EssPwd::setFromHex(const char * const hex)
{
    if (hex == NULL)
        return -1;
    if (strlen(hex) % 2 != 0)
        return -1;
    /* key should have maximum 64 hexadecimal digits */
    if (strlen(hex) > 2 * sizeof(mPwd))
        return -1;
    mSize = strlen(hex) / 2;
    return from_hex(hex, mPwd, mSize);
}

void EssCmd::EssPwd::toHex(char * const str)
{
    to_hex(mPwd, str, mSize);
}

size_t EssCmd::EssPwd::size(void) const
{
    return mSize;
}


/**
 * ARKHAM-30: Encrypt container application data
 * Create random key and encrypt it using <code>passwd</code>.
 */
int EssCmd::createEss(int cid, EssPwd * const pwd, EssKey * const key) {
    int ret;
    uint8_t master_key[ESS_KEY_LEN];
    uint8_t salt[ESS_SALT_LEN];

    ret = ess_create_master_key(cid, (char *) pwd->get(), pwd->size(), master_key, salt);
    if (ret < 0)
        return ret;

    ret = key->setKey(master_key);
    if (ret < 0)
        return ret;
    ret = key->setSalt(salt);
    if (ret < 0)
        return ret;

    SLOGD("ESS key is created");
    return 0;
}

/**
 * ARKHAM-30: Encrypt container application data
 * Mounts ecpryptfs on directory <code>path</code>.
 */
int EssCmd::mountEss(int cid, const char * const path, EssPwd * const pwd,  EssKey * const key,
                     int user_id, int group_id) {
    int ret;

    ret = ess_mount_ecryptfs(cid, path, (char *) pwd->get(), pwd->size(), user_id, group_id,
                             (uint8_t*) key->getKey(), (uint8_t*) key->getSalt());
    if (ret < 0)
        return ret;

    SLOGD("ESS is mounted for %s directory", path);
    return 0;
}

/**
 * ARKHAM-30: Encrypt container application data
 * Unmounts ecryptfs on directory <code>path</code>.
 */
int EssCmd::unmountEss(const char * const path) {
    int ret;

    ret = ess_unmount_ecryptfs(path);
    if (ret < 0)
        return ret;

    SLOGD("ESS is unmounted for %s directory", path);
    return 0;
}

/**
 * ARKHAM-30: Encrypt container application data
 * Unmounts all mounted ecryptfs directories.
 */
int EssCmd::unmountAllEss() {
    int ret;

    ret = ess_unmount_all_ecryptfs();
    if (ret < 0)
        return ret;

    SLOGD("ESS unmounted all ecryptfs directories");
    return 0;
}


/**
 * ARKHAM-30: Encrypt container application data
 * Change password for user.
 */
int EssCmd::changePasswordEss(int cid, EssPwd * const oldPwd, EssPwd * const newPwd,
                              EssKey * const key) {
    int ret;
    uint8_t new_master_key[ESS_KEY_LEN];

    ret = ess_changepw(cid, (char *) oldPwd->get(), oldPwd->size(), (char *) newPwd->get(),
                       newPwd->size(), (uint8_t *)key->getSalt(), (uint8_t*)key->getKey(),
                       new_master_key);
    if (ret < 0)
        return ret;

    ret = key->setKey(new_master_key);
    if (ret < 0)
        return ret;

    SLOGD("ESS password changed");
    return 0;
}

/**
 * ARKHAM-30: Encrypt container application data
 * Delete container with cid <code>cid</code>.
 */
int EssCmd::deleteEss(int cid) {
    int ret;

    ret = ess_delete(cid);
    if (ret < 0)
        return ret;

    SLOGD("ESS delete container %d", cid);
    return 0;
}

/**
 * ARKHAM-30: Encrypt container application data
 * Enable container with cid <code>cid</code>.
 */
int EssCmd::enableEss(int cid) {
    int ret;

    ret = ess_enable(cid);
    if (ret < 0)
        return ret;

    SLOGD("ESS enable container %d", cid);
    return 0;
}

/**
 * ARKHAM-30: Encrypt container application data
 * Disable container with cid <code>cid</code>.
 */
int EssCmd::disableEss(int cid) {
    int ret;

    ret = ess_disable(cid);
    if (ret < 0)
        return ret;

    SLOGD("ESS disable container %d", cid);
    return 0;
}

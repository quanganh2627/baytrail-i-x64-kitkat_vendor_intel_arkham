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
 * ARKHAM-248: Use Chaabi for device specific encryption.
 * This file is used for container encryption commands.
 * Encryption is both simulated in SW and uses Chaabi FW.
 */

#ifndef _ESS_H
#define _ESS_H

/* length in bytes */
#define ESS_KEY_LEN 16
#define ESS_SALT_LEN 16
#define ESS_MAX_PWD_LEN 36

#ifdef __cplusplus
extern "C" {
#endif
        void to_hex(const uint8_t * const src, char *const dest,
                    size_t src_len);
        int from_hex(const char *const src, uint8_t * const dest,
                     size_t dest_len);
        int ess_create_master_key(int cid, const char *const passwd,
                                  int passwd_len, uint8_t * const master_key,
                                  uint8_t * const salt);
        int ess_changepw(int cid, const char *const old_passwd,
                         int old_passwd_len, const char *const new_passwd,
                         int new_passwd_len, const uint8_t * const salt,
                         const uint8_t * const old_master_key,
                         uint8_t * const new_master_key);
        int ess_mount_ecryptfs(int cid, const char *const path,
                               const char *const passwd, int passwd_len,
                               int uid, int cgid,
                               const uint8_t * const master_key,
                               const uint8_t * const salt);
        int ess_unmount_ecryptfs(const char *const path);
        int ess_unmount_all_ecryptfs(void);
        int ess_delete(int cid);
        int ess_enable(int cid);
        int ess_disable(int cid);

#ifdef __cplusplus
}
#endif
#endif

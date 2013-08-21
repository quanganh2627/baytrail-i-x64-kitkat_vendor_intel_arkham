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

#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#define LOG_TAG "Ess"
#include "cutils/log.h"
#include "cryptfs.h"
#include "ess.h"
#include "VolumeManager.h"

/*
 * There are 2 posibilities for using chaabi: software simulation or using HW chaabi.
 * While we do not have the functionality implemented in the chaabi FW, we cannot
 * use HW Chaabi. However, we are using HW hooks to ensure integration when the FW
 * will be implemented: for this, we call HW Chaabi but we override the values using
 * SW Chaabi (since HW Chaabi will not return valid results until features are implemented
 * in FW).
 * Software simulation should be removed when FW container features are implemented.
 */
#define SIMULATE_CHAABI_IN_SW
/* Enable HW Chaabi */
//#define ENABLE_CHAABI_IN_HW

#ifdef ENABLE_CHAABI_IN_HW
/* Include chaabi container FW API */
#include <libcontainer_sec/container_sec.h>
#endif

#define ESS_HASH_COUNT 2000
#define ESS_IV_LEN 16
#define ESS_ECRYPTFS_KEY_LEN (ESS_KEY_LEN + ESS_IV_LEN) //32
#define ESS_ECRYPTFS_SIG_LEN SHA512_DIGEST_LENGTH       //64

#define MAX_LINE_LENGTH 1024

#define ESS_DEBUG 1

#define WORD_HIGH_BYTE_MASK 0xFF00
#define WORD_LOW_BYTE_MASK 0x00FF

/* Big enough to hold a 256 bit key and 256 bit IV */
#define KEY_MAX_LEN 32
#define IV_MAX_LEN 32

/*
 * Helpers
 */

#define min(a, b) (((a) < (b))?(a):(b))

/**
 * ARKHAM-30: Convert a byte array to a hex string.
 */
void to_hex(const uint8_t * const src, char *const dest, size_t src_len)
{
        size_t i;
        char *ptr;
        int ret;

        ptr = dest;
        for (i = 0; i < src_len; i++) {
                /* Write maximum 2 hexadecimal digits + \0 */
                ret = snprintf(ptr, 3, "%02x", src[i]);
                /* If output was truncated */
                if (ret > 2)
                        ret = 2;
                ptr += ret;
        }
}

/**
 * ARKHAM-30: Convert a hex string to a byte array.
 */
int from_hex(const char *const src, uint8_t * const dest, size_t dest_len)
{
        char hex_digit[3];
        char *endptr = NULL;
        size_t i;

        if ((src == NULL) || (dest == NULL) || (strlen(src) > 2 * dest_len))
                return -1;

        memset(dest, 0, dest_len);
        for (i = 0; i < dest_len; i++) {
                hex_digit[0] = src[i * 2];
                hex_digit[1] = src[i * 2 + 1];
                hex_digit[2] = '\0';
                errno = 0;
                dest[i] = (uint8_t) strtoul(hex_digit, &endptr, 16);
                if ((errno != 0) || (endptr == hex_digit) || (*endptr != '\0')) {
                        return -1;
                }
        }
        return 0;
}

/**
 * Log the output of lsof command in logcat.
 * This is used for debug pourposes in case
 * unmount fails, to determine which processes
 * are using the folder to unmount.
 */
static int dump_lsof(const char *const path)
{
        FILE *fp;
        char command[MAX_LINE_LENGTH];
        char line[MAX_LINE_LENGTH];

        sprintf(command, "lsof | grep %s", path);

        fp = popen(command, "r");
        if (!fp) {
                SLOGD("Error running %s (%s)", command, strerror(errno));
                return -1;
        }

        SLOGD("%s: ", command);
        while (fgets(line, sizeof(line), fp)) {
                SLOGD("%s", line);
        }

        pclose(fp);
        return 0;
}

/*
 * add_key and keyctl system calls
 */

/* key serial number */
typedef int32_t key_serial_t;

/* special process keyring shortcut IDs */
#define KEY_SPEC_PROCESS_KEYRING        -2      /* - key ID for process-specific keyring */

/* keyctl commands */
#define KEYCTL_UNLINK                   9       /* unlink a key from a keyring */
#define KEYCTL_SETPERM                  5       /* set perms on a key */
#define KEYCTL_SEARCH                   10      /* search for a key in a keyring */

#define KEYCTL_USER_KEYRING "user"

#define KEY_PERM_POSSESOR_VIEW 0x01000000
#define KEY_PERM_POSSESOR_READ 0x02000000
#define KEY_PERM_POSSESOR_WRITE 0x04000000
#define KEY_PERM_POSSESOR_SEARCH 0x08000000

#define __weak __attribute__((weak))

key_serial_t __weak add_key(const char *const type,
                            const char *const description,
                            const void *const payload,
                            size_t plen, key_serial_t ringid)
{
        return syscall(__NR_add_key, type, description, payload, plen, ringid);
}

static inline long __keyctl(int cmd,
                            unsigned long arg2,
                            unsigned long arg3,
                            unsigned long arg4, unsigned long arg5)
{
        return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
}

long __weak keyctl(int cmd, ...)
{
        va_list va;
        unsigned long arg2, arg3, arg4, arg5;

        va_start(va, cmd);
        arg2 = va_arg(va, unsigned long);
        arg3 = va_arg(va, unsigned long);
        arg4 = va_arg(va, unsigned long);
        arg5 = va_arg(va, unsigned long);
        va_end(va);

        return __keyctl(cmd, arg2, arg3, arg4, arg5);
}

/*
 * Ecryptfs structures & definitions for add_key
 */

#ifndef ECRYPTFS_VERSION_MAJOR
#define ECRYPTFS_VERSION_MAJOR 0x00
#endif
#ifndef ECRYPTFS_VERSION_MINOR
#define ECRYPTFS_VERSION_MINOR 0x04
#endif

#define ECRYPTFS_MAX_PASSWORD_LENGTH 64
#define ECRYPTFS_MAX_PASSPHRASE_BYTES ECRYPTFS_MAX_PASSWORD_LENGTH
#define ECRYPTFS_SALT_SIZE 8
#define ECRYPTFS_SALT_SIZE_HEX (ECRYPTFS_SALT_SIZE*2)
#define ECRYPTFS_SIG_SIZE 8
#define ECRYPTFS_SIG_SIZE_HEX (ECRYPTFS_SIG_SIZE*2)
#define ECRYPTFS_SIG_SIZE_HEX_STRING "16"
#define ECRYPTFS_PASSWORD_SIG_SIZE ECRYPTFS_SIG_SIZE_HEX
#define ECRYPTFS_MAX_KEY_BYTES 64
#define ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES 512
#define ECRYPTFS_MAX_KEY_MOD_NAME_BYTES 16

#define PGP_DIGEST_ALGO_SHA512   10

struct ecryptfs_session_key {
#define ECRYPTFS_USERSPACE_SHOULD_TRY_TO_DECRYPT 0x00000001
#define ECRYPTFS_USERSPACE_SHOULD_TRY_TO_ENCRYPT 0x00000002
#define ECRYPTFS_CONTAINS_DECRYPTED_KEY 0x00000004
#define ECRYPTFS_CONTAINS_ENCRYPTED_KEY 0x00000008
        int32_t flags;
        int32_t encrypted_key_size;
        int32_t decrypted_key_size;
        uint8_t encrypted_key[ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES];
        uint8_t decrypted_key[ECRYPTFS_MAX_KEY_BYTES];
};

struct ecryptfs_password {
        int32_t password_bytes;
        int32_t hash_algo;
        int32_t hash_iterations;
        int32_t session_key_encryption_key_bytes;
#define ECRYPTFS_PERSISTENT_PASSWORD             0x01
#define ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET  0x02
        uint32_t flags;
        /* Iterated-hash concatenation of salt and passphrase */
        uint8_t session_key_encryption_key[ECRYPTFS_MAX_KEY_BYTES];
        uint8_t signature[ECRYPTFS_PASSWORD_SIG_SIZE + 1];
        /* Always in expanded hex */
        uint8_t salt[ECRYPTFS_SALT_SIZE];
};

struct ecryptfs_private_key {
        uint32_t key_size;
        uint32_t data_len;
        uint8_t signature[ECRYPTFS_PASSWORD_SIG_SIZE + 1];
        char key_mod_alias[ECRYPTFS_MAX_KEY_MOD_NAME_BYTES + 1];
        uint8_t data[];
};

enum ecryptfs_token_types { ECRYPTFS_PASSWORD, ECRYPTFS_PRIVATE_KEY };

/* This structure must be identical to that as defined in the kernel. */
struct ecryptfs_auth_tok {
        uint16_t version;       /* 8-bit major and 8-bit minor */
        uint16_t token_type;
#define ECRYPTFS_ENCRYPT_ONLY 0x00000001
        uint32_t flags;
        struct ecryptfs_session_key session_key;
        uint8_t reserved[32];
        union {
                struct ecryptfs_password password;
                struct ecryptfs_private_key private_key;
        } token;
} __attribute__ ((packed));

/**
 * ARKHAM-30: Add a token to the kernel keyring.
 * This will be used by ecryptfs as encryption key.
 */
static int add_tok_to_keyring(const struct ecryptfs_auth_tok *const tok,
                              const char *const sig)
{
        int ret;
        key_serial_t id;

        id = keyctl(KEYCTL_SEARCH, KEY_SPEC_PROCESS_KEYRING,
                    KEYCTL_USER_KEYRING, sig, 0);
        if (id >= 0) {
                /* key already in keychain */
                return 0;
        }

        id = add_key(KEYCTL_USER_KEYRING, sig, tok,
                     sizeof(struct ecryptfs_auth_tok),
                     KEY_SPEC_PROCESS_KEYRING);
        if (id < 0) {
                ret = -errno;
                SLOGE("Error adding key with sig %s; ret = [%d]\n", sig, errno);
                if (ret == -EDQUOT)
                        SLOGE
                            ("Error adding key to keyring - keyring is full\n");
                return ret;
        }

        ret =
            keyctl(KEYCTL_SETPERM, id,
                   KEY_PERM_POSSESOR_VIEW | KEY_PERM_POSSESOR_READ |
                   KEY_PERM_POSSESOR_WRITE | KEY_PERM_POSSESOR_SEARCH);
        if (ret < 0) {
                ret = -errno;
                SLOGE
                    ("Error setting permissions for key with sig %s; ret = [%d]\n",
                     sig, errno);
                return ret;
        }

        return 0;
}

/**
 * ARKHAM-30: Remove a token to the kernel keyring.
 * This will be used by ecryptfs as encryption key.
 */
static int remove_tok_from_keyring(const char *const sig)
{
        int ret;
        key_serial_t id;

        id = keyctl(KEYCTL_SEARCH, KEY_SPEC_PROCESS_KEYRING,
                    KEYCTL_USER_KEYRING, sig, 0);
        if (id < 0) {
                /* if key is not in keychain means it's already clean */
                return 0;
        }

        ret = keyctl(KEYCTL_UNLINK, id, KEY_SPEC_PROCESS_KEYRING);
        if (ret < 0) {
                SLOGE("Failed to unlink key with sig %s: %s\n",
                      sig, strerror(ret));
                return ret;
        }
        return 0;
}

/**
 * ARKHAM-30: Fill in the token structure to send to the kernel keyring.
 * This will contain the password, encryption key and salt for
 * the container and will be used by ecryptfs.
 */
static int get_tok_for_keyring(struct ecryptfs_auth_tok *const auth_tok,
                               const char *const passphrase_sig,
                               const char *const salt,
                               const char *const session_key_encryption_key)
{
        int rc = 0;
        int major, minor;
        int max_key_bytes = min(ECRYPTFS_MAX_KEY_BYTES, ESS_ECRYPTFS_KEY_LEN);
        int max_salt_bytes = min(ECRYPTFS_SALT_SIZE, ESS_SALT_LEN);

        memset(auth_tok, 0, sizeof(struct ecryptfs_auth_tok));
        major = ECRYPTFS_VERSION_MAJOR;
        minor = ECRYPTFS_VERSION_MINOR;
        /* Version = major minor (combined into a 16 bytes value) */
        auth_tok->version = (((uint16_t) (major << 8) & WORD_HIGH_BYTE_MASK)
                             | ((uint16_t) minor & WORD_LOW_BYTE_MASK));
        auth_tok->token_type = ECRYPTFS_PASSWORD;
        strncpy((char *)auth_tok->token.password.signature, passphrase_sig,
                ECRYPTFS_PASSWORD_SIG_SIZE);
        memcpy(auth_tok->token.password.salt, salt, max_salt_bytes);
        memcpy(auth_tok->token.password.session_key_encryption_key,
               session_key_encryption_key, max_key_bytes);
        auth_tok->token.password.session_key_encryption_key_bytes =
            max_key_bytes;
        auth_tok->token.password.flags |=
            ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET;
        /* The kernel code will encrypt the session key. */
        auth_tok->session_key.encrypted_key[0] = 0;
        auth_tok->session_key.encrypted_key_size = 0;
        /* Default; subject to change by kernel eCryptfs */
        auth_tok->token.password.hash_algo = PGP_DIGEST_ALGO_SHA512;
        auth_tok->token.password.flags &= ~(ECRYPTFS_PERSISTENT_PASSWORD);
        return rc;
}

/**
 * ARKHAM-30: Mount ecryptfs on top of the given folder.
 * After ecryptfs is mounted on a folder, all data written to that folder
 * will be encrypted.
 */
static int ecryptfs_mount(const char *const source, const char *const target,
                          const char *const opts)
{
        int ret;

        ret = mount(source, target, "ecryptfs", 0, opts);
        if (ret < 0) {
                ret = -errno;
                SLOGE("Could not mount ecryptfs - error %d: %s", errno,
                      strerror(errno));
                return ret;
        }
        return 0;
}

/**
 * ARKHAM-30: Unmount ecryptfs on top of the given folder.
 * After ecryptfs is unmounted on a folder, all data written to that folder
 * will no longer be encrypted. Data written while ecryptfs was mounted will
 * not be accesible anymore.
 * If unmount fails, we retry for 5 times before returning error.
 */
static int ecryptfs_wait_and_unmount(const char *const target)
{
        int i, ret;
#define WAIT_UNMOUNT_COUNT 5

        for (i = 0; i < WAIT_UNMOUNT_COUNT; i++) {
                ret = umount(target);
                if (ret == 0)
                        break;
                /* EINVAL is returned if the directory is not a mountpoint,
                 * i.e. there is no filesystem mounted there.  So just get out.
                 */
                if (errno == EINVAL)
                        break;
                sleep(1);
        }

        if (i == WAIT_UNMOUNT_COUNT) {
                ret = -errno;
                SLOGE("Could not unmount ecryptfs - error %d: %s", errno,
                      strerror(errno));
                return ret;
        }

        return 0;
}

/**
 * ARKHAM-30: Turn the password into a key and IV that can decrypt the master
 * key.
 * This is very similar to the pbkdf2 function from system/vold/cryptfs.c,
 * with 2 differences:
 * 1. passwd_len is used instead of strlen(passwd) since in our case passwd
 * is a byte array and not a string
 * 2. we are using our own constants for key lenght and salt lenght
 */
static void pbkdf2(const char *const passwd, int passwd_len,
                   const uint8_t * const salt, uint8_t * const ikey)
{
        PKCS5_PBKDF2_HMAC_SHA1(passwd, passwd_len, salt, ESS_SALT_LEN,
                               ESS_HASH_COUNT, ESS_KEY_LEN + ESS_IV_LEN, ikey);
}

/**
 * ARKHAM-30: Encrypts the master key using CBC 128 bytes algorithm.
 * This is similar to the same function from system/vold/cryptfs.c,
 * but we are using our own constants for key and salt lenght.
 * Returns the encrypted key.
 */
static int encrypt_master_key(const char *const passwd, int passwd_len,
                              const uint8_t * const salt,
                              const uint8_t * const decrypted_master_key,
                              uint8_t * const encrypted_master_key)
{
        uint8_t ikey[KEY_MAX_LEN + IV_MAX_LEN] = { 0 };
        EVP_CIPHER_CTX e_ctx;
        int encrypted_len, final_len;

        /* Turn the password into a key and IV that can decrypt the master key */
        pbkdf2(passwd, passwd_len, salt, ikey);

        /* Initialize the decryption engine */
        if (!EVP_EncryptInit
            (&e_ctx, EVP_aes_128_cbc(), ikey, ikey + ESS_KEY_LEN)) {
                SLOGE("EVP_EncryptInit failed\n");
                return -1;
        }
        EVP_CIPHER_CTX_set_padding(&e_ctx, 0);  /* Turn off padding as our data is block aligned */

        /* Encrypt the master key */
        if (!EVP_EncryptUpdate(&e_ctx, encrypted_master_key, &encrypted_len,
                               decrypted_master_key, ESS_KEY_LEN)) {
                SLOGE("EVP_EncryptUpdate failed\n");
                return -1;
        }
        if (!EVP_EncryptFinal
            (&e_ctx, encrypted_master_key + encrypted_len, &final_len)) {
                SLOGE("EVP_EncryptFinal failed\n");
                return -1;
        }

        if (encrypted_len + final_len != ESS_KEY_LEN) {
                SLOGE("EVP_Encryption length check failed with %d, %d bytes\n",
                      encrypted_len, final_len);
                return -1;
        } else {
                return 0;
        }
}

/**
 * ARKHAM-30: Decrypts the master key using CBC 128 bytes algorithm.
 * This is similar to the same function from system/vold/cryptfs.c,
 * but we are using our own constants for key and salt lenght.
 * Returns the decrypted key.
 */
static int decrypt_master_key(const char *const passwd, int passwd_len,
                              const uint8_t * const salt,
                              const uint8_t * const encrypted_master_key,
                              uint8_t * const decrypted_master_key)
{
        uint8_t ikey[KEY_MAX_LEN + IV_MAX_LEN] = { 0 };
        EVP_CIPHER_CTX d_ctx;
        int decrypted_len, final_len;

        /* Turn the password into a key and IV that can decrypt the master key */
        pbkdf2(passwd, passwd_len, salt, ikey);

        /* Initialize the decryption engine */
        if (!EVP_DecryptInit
            (&d_ctx, EVP_aes_128_cbc(), ikey, ikey + ESS_KEY_LEN)) {
                return -1;
        }
        /* Turn off padding as our data is block aligned */
        EVP_CIPHER_CTX_set_padding(&d_ctx, 0);
        /* Decrypt the master key */
        if (!EVP_DecryptUpdate(&d_ctx, decrypted_master_key, &decrypted_len,
                               encrypted_master_key, ESS_KEY_LEN)) {
                return -1;
        }
        if (!EVP_DecryptFinal
            (&d_ctx, decrypted_master_key + decrypted_len, &final_len)) {
                return -1;
        }

        if (decrypted_len + final_len != ESS_KEY_LEN) {
                return -1;
        } else {
                return 0;
        }
}

/**
 * ARKHAM-30: Generate an encrypted master key and salt for container
 * encryption.
 * Generates a random key and salt and encrypts them using the user
 * password. The encryption algorithm used is CBC 128 bytes.
 * Returns the encrypted key and the salt.
 */
static int create_encrypted_random_key(const char *const passwd, int passwd_len,
                                       uint8_t * const master_key,
                                       uint8_t * const salt)
{
        int fd;
        uint8_t key_buf[ESS_KEY_LEN];
        EVP_CIPHER_CTX e_ctx;
        int encrypted_len, final_len;

        /* Get some random bits for a key */
        fd = open("/dev/urandom", O_RDONLY);
        read(fd, key_buf, sizeof(key_buf));
        read(fd, salt, ESS_SALT_LEN);
        close(fd);

        /* Now encrypt it with the password */
        return encrypt_master_key(passwd, passwd_len, salt, key_buf,
                                  master_key);
}

/*
 * API called by vold commands in VolumeManager
 */

#define MAX_OPTION_LENGTH 256

/**
 * ARKHAM-30: Generate an encrypted master key and salt for container
 * encryption.
 * Generates a random key and salt and encrypts them using the user
 * password. The encryption algorithm used is CBC 128 bytes.
 * The algorithm is implemented in SW.
 * Returns the encrypted key and the salt.
 */
static int ess_create_master_key_sw(const char *passwd, int passwd_len,
                                    uint8_t * const master_key,
                                    uint8_t * const salt)
{
        /* Generate encrypted master key */
        if (create_encrypted_random_key
            ((char *)passwd, passwd_len, master_key, salt)) {
                SLOGE("Cannot create encrypted master key\n");
                return -1;
        }
        return 0;
}

/**
 * ARKHAM-30: Generate an encrypted master key and salt for container
 * encryption.
 * Generates a random key and salt and encrypts them using the user
 * password.
 * One of 2 algorithms can be chosen at compile time:
 * 1. SW simulation using CBC 128 bytes encryption algorithm.
 * 2. HW encryption using Chaabi
 * Returns the encrypted key and the salt.
 */
int ess_create_master_key(int cid, const char *const passwd, int passwd_len,
                          uint8_t * const master_key, uint8_t * const salt)
{
        int ret;

#ifdef ENABLE_CHAABI_IN_HW
        ret = cont_sec_create(cid, passwd, passwd_len, master_key, ESS_KEY_LEN);
        if (ret != CONT_SUCCESS) {
                SLOGE("Cannot create encrypted master key (error = 0x%x)\n",
                      ret);
                return -1;
        }

        /* salt is not used with chaabi */
        memset(salt, 0, ESS_SALT_LEN);
#endif

#ifdef SIMULATE_CHAABI_IN_SW
        ret = ess_create_master_key_sw(passwd, passwd_len, master_key, salt);
        if (ret < 0)
                return ret;
#endif
        return 0;
}

/**
 * ARKHAM-30: Change container encryption password.
 * Encrypt the ecryptfs key using the new user provided password.
 * The encryption algorithm used is CBC 128 bytes.
 * The ecryptfs original key and salt remain the same.
 * The algorithm is implemented in SW.
 * Returns the encrypted key.
 */
static int ess_changepw_sw(const char *const old_passwd, int old_passwd_len,
                           const char *const new_passwd, int new_passwd_len,
                           const uint8_t * const salt,
                           const uint8_t * const old_master_key,
                           uint8_t * const const new_master_key)
{
        uint8_t decrypted_old_master_key[ESS_KEY_LEN];
        int ret;

        /* Get decrypted master key */
        ret =
            decrypt_master_key((char *)old_passwd, old_passwd_len, salt,
                               old_master_key, decrypted_old_master_key);
        if (ret < 0) {
                SLOGE("Error decrypting master key\n");
                return -1;
        }

        /* Encrypt the master key with the new passwod */
        ret =
            encrypt_master_key((char *)new_passwd, new_passwd_len, salt,
                               decrypted_old_master_key, new_master_key);
        if (ret < 0) {
                SLOGE("Error encrypting new master key\n");
                return -1;
        }

        return 0;
}

/**
 * ARKHAM-30: Change container encryption password.
 * Encrypt the ecryptfs key using the new user provided password.
 * The ecryptfs original key and salt remain the same.
 * One of 2 algorithms can be chosen at compile time:
 * 1. SW simulation using CBC 128 bytes encryption algorithm.
 * 2. HW encryption using Chaabi
 * Returns the encrypted key.
 */
int ess_changepw(int cid, const char *const old_passwd, int old_passwd_len,
                 const char *const new_passwd, int new_passwd_len,
                 const uint8_t * const salt,
                 const uint8_t * const old_master_key,
                 uint8_t * const new_master_key)
{
        int ret;

#ifdef ENABLE_CHAABI_IN_HW
        ret =
            cont_sec_changepwd(cid, old_passwd, old_passwd_len, new_passwd,
                               new_passwd_len, old_master_key,
                               ESS_KEY_LEN, new_master_key, ESS_KEY_LEN);
        if (ret != CONT_SUCCESS) {
                SLOGE("Cannot change password (error = 0x%x)\n", ret);
                return -1;
        }
#endif

#ifdef SIMULATE_CHAABI_IN_SW
        ret =
            ess_changepw_sw(old_passwd, old_passwd_len, new_passwd,
                            new_passwd_len, salt, old_master_key,
                            new_master_key);
        if (ret < 0)
                return ret;
#endif

        return 0;
}

/**
 * ARKHAM-30: Generate ecryptfs key and signature starting from user
 * password, encrypted key and salt.
 * The enctypted key is decrypted using the given user password,
 * A combined key is generated based on the decrypted key and container id.
 * The resulting key will be used for ecryptfs. A signature of this key
 * is also computed and returned.
 * Generating the key is implemented in SW.
 * Returns ecryptfs key and signature.
 */
static int get_key_and_sig_sw(const char *const passwd, int passwd_len,
                              int cgid, const uint8_t * const master_key,
                              const uint8_t * const salt,
                              uint8_t * const ecryptfs_key,
                              uint8_t * const ecryptfs_sig)
{
        int ret;
        uint8_t decrypted_master_key[ESS_KEY_LEN];
#define COMBINED_KEY_SIZE (ESS_KEY_LEN + sizeof(int))
        char combined_key[COMBINED_KEY_SIZE];

        /* Get decrypted master key */
        ret =
            decrypt_master_key((char *)passwd, passwd_len, salt, master_key,
                               decrypted_master_key);
        if (ret < 0) {
                SLOGE("Error decrypting master key\n");
                return ret;
        }

        /* combined_key = master_key#cgid */
        memcpy(combined_key, decrypted_master_key, ESS_KEY_LEN);
        memcpy(combined_key + ESS_KEY_LEN, &cgid, sizeof(int));
        pbkdf2(combined_key, COMBINED_KEY_SIZE, salt, ecryptfs_key);

        /* signature = hash of ecryptfs_key */
        SHA512(ecryptfs_key, ESS_ECRYPTFS_KEY_LEN, ecryptfs_sig);
        return 0;
}

/**
 * ARKHAM-30: Generate ecryptfs key and signature starting from user
 * password, encrypted key and salt.
 * The enctypted key is decrypted using the given user password,
 * A combined key is generated based on the decrypted key and container id.
 * The resulting key will be used for ecryptfs. A signature of this key
 * is also computed and returned.
 * One of 2 algorithms can be chosen at compile time:
 * 1. SW simulation using CBC 128 bytes encryption algorithm.
 * 2. HW encryption using Chaabi
 * Returns ecryptfs key and signature.
 */

static int get_key_and_sig(int cid, const char *const passwd, int passwd_len,
                           int cgid, const uint8_t * const master_key,
                           const uint8_t * const salt,
                           uint8_t * const ecryptfs_key,
                           char *const ecryptfs_sig_hex)
{
        int ret;
        uint8_t ecryptfs_sig[ESS_ECRYPTFS_SIG_LEN];

#ifdef ENABLE_CHAABI_IN_HW
        ret =
            cont_sec_getinfo(cid, passwd, passwd_len, master_key,
                             ESS_KEY_LEN, ecryptfs_key, ESS_ECRYPTFS_KEY_LEN,
                             ecryptfs_sig, ESS_ECRYPTFS_SIG_LEN);
        if (ret != CONT_SUCCESS) {
                SLOGE("Cannot create encrypted master key (error = 0x%x)\n",
                      ret);
                return -1;
        }
#endif

#ifdef SIMULATE_CHAABI_IN_SW
        ret =
            get_key_and_sig_sw(passwd, passwd_len, cgid, master_key, salt,
                               ecryptfs_key, ecryptfs_sig);
        if (ret < 0)
                return ret;
#endif

        /* we trucate the signature to ECRYPTFS_SIG_SIZE since this is what ecryptfs expects */
        to_hex(ecryptfs_sig, ecryptfs_sig_hex, ECRYPTFS_SIG_SIZE);
        SLOGD("User sig = %s\n", ecryptfs_sig_hex);

        return 0;
}

/**
 * ARKHAM-30: Check if ecryptfs is already mounted on the given path.
 * Searches for the given mountpoint in /proc/mounts.
 * If ecryptfs is already mounted on the given path, it also
 * returns the mount options.
 */
static int is_mounted(const char *const path, char *const mount_options)
{
        char device[MAX_OPTION_LENGTH];
        char mount_path[MAX_OPTION_LENGTH];
        char type[MAX_OPTION_LENGTH];
        FILE *fp;
        char line[MAX_LINE_LENGTH];
        int found = 0;

        fp = fopen("/proc/mounts", "r");
        if (!fp) {
                SLOGE("Error opening /proc/mounts (%s)", strerror(errno));
                return -1;
        }

        /* Looking for lines that look like:
         * <path> <path> ecryptfs <mount_options>
         * e.g.: /data/user/10 /data/user/10 ecryptfs ...
         */
        found = 0;
        while (fgets(line, sizeof(line), fp)) {
                sscanf(line, "%255s %255s %255s %255s", device, mount_path,
                       type, mount_options);

                /* Search for lines that start with <path> <path> ecryptfs */
                if (!strncmp(type, "ecryptfs", strlen("ecryptfs")) &&
                    !strncmp(device, path, strlen(path)) &&
                    !strncmp(mount_path, path, strlen(path))) {
                        found = 1;
                        break;
                }
        }

        fclose(fp);
        return found;

}

/**
 * ARKHAM-30: Add ecryptfs key to the kernel keyring.
 */
static int add_key_to_keyring(const uint8_t * const key,
                              const char *const sig_hex,
                              const uint8_t * const salt)
{
        int ret = 0;
        struct ecryptfs_auth_tok tok;

        ret = get_tok_for_keyring(&tok, sig_hex, (char *)salt, (char *)key);
        if (ret < 0) {
                SLOGE("Error generating payload");
                return ret;
        }

        ret = add_tok_to_keyring(&tok, sig_hex);
        if (ret < 0) {
                SLOGE("Error adding key to keyring");
                return ret;
        }
        return 0;
}

/**
 * ARKHAM-30: Mount ecryptfs on the given path.
 * After mounting ecryptfs, all data written to the given path will be
 * encrypted. The folder will have rwx rights for owner and given group
 * (cgid) and no rights for others.
 */
int ess_mount_ecryptfs(int cid, const char *const path,
                       const char *const passwd, int passwd_len, int uid,
                       int cgid, const uint8_t * const master_key,
                       const uint8_t * const salt)
{
        int ret = 0;
        uint8_t ecryptfs_key[ESS_ECRYPTFS_KEY_LEN];
        char ecryptfs_sig_hex[ECRYPTFS_SIG_SIZE_HEX + 1];
        char mount_options[MAX_OPTION_LENGTH];
        struct ecryptfs_auth_tok tok;
        struct stat file_stat;

        /* Nothing to do if ecryptfs is already mounted on <path> */
        if (is_mounted(path, mount_options)) {
                SLOGW("ecryptfs is already mounted on %s\n", path);
                return 0;
        }

        /* decrypt key and generate ecryptfs fefek key and signature */
        ret =
            get_key_and_sig(cid, passwd, passwd_len, cgid, master_key, salt,
                            ecryptfs_key, ecryptfs_sig_hex);
        if (ret < 0)
                return ret;

        /* add ecryptfs key to kernel keyring */
        ret = add_key_to_keyring(ecryptfs_key, ecryptfs_sig_hex, salt);
        if (ret < 0)
                return ret;

        /* create directory to be mounted if it does not exist.
         * When the container is created, ecryptfs mount is called before
         * the user directory is created. In that case, we create it here */
        ret = stat(path, &file_stat);
        if (ret == -1 && errno == ENOENT) {
                errno = 0;
                ret = mkdir(path, 0770);
                if (ret < 0) {
                        SLOGE("Error creating directory %s: %s", path,
                              strerror(errno));
                        return ret;
                }
        }

        /* mount ecryptfs */
        snprintf(mount_options, sizeof(mount_options),
                 "ecryptfs_sig=%s,ecryptfs_fnek_sig=%s,ecryptfs_cipher=aes,ecryptfs_key_bytes=%d",
                 ecryptfs_sig_hex, ecryptfs_sig_hex,
                 ESS_ECRYPTFS_KEY_LEN);
        SLOGD("Mount opts: %s", mount_options);
        ret = ecryptfs_mount(path, path, mount_options);
        if (ret < 0) {
                SLOGE("Error mounting ecryptfs");
                return ret;
        }

        ret = chown(path, uid, cgid);
        if (ret < 0) {
                SLOGE("Error changing group");
                return ret;
        }

        ret = chmod(path, 0770);
        if (ret < 0) {
                SLOGE("Error changing permission");
                return ret;
        }

        return 0;
}

/**
 * ARKHAM-30: Get signature for mounted ecryptfs on the given path.
 * Given the mount options read from /proc/mounts, parse
 * them and extract ecryptfs signature.
 */
static int get_sig_from_mount_options(const char *const path,
                                      const char *const mount_options,
                                      char *const ecryptfs_sig_hex)
{
        char *option = NULL, *tmp = NULL, *options = NULL;
        int ret = 0, no_found_sigs = 0;

        /* Search for ecryptfs_sig through comma-separated mount options */
        options = strdup(mount_options);
        if (options == NULL) {
                SLOGE("cannot allocate memory for mount options string");
                return -1;
        }
        option = strtok_r(options, ",", &tmp);
        while (option != NULL && no_found_sigs < 2) {
                /* ecryptfs_sig=<ecryptfs_sig_hex> */
                if (!strncmp(option, "ecryptfs_sig", strlen("ecryptfs_sig"))) {
                        ret =
                            sscanf(option,
                                   "ecryptfs_sig=%" ECRYPTFS_SIG_SIZE_HEX_STRING
                                   "s", ecryptfs_sig_hex);
                        if (ret != 1) {
                                SLOGE
                                    ("ecryptfs signature has incorrect format in"
                                     " ecryptfs mount options for %s\n", path);
                                free(options);
                                return -1;
                        }
                        no_found_sigs++;
                }
                option = strtok_r(NULL, ",", &tmp);
        }

        if (no_found_sigs < 1) {
                SLOGE("ecryptfs signature not found in ecryptfs mount "
                      "options for %s\n", path);
                free(options);
                return -1;
        }
        free(options);
        return 0;
}

/**
 * ARKHAM-30: Unmount ecryptfs from given path.
 * Unmount ecryptfs and retry several times if it fails.
 * Cleanup kernel keyring.
 */
static int unmount_mounted_ecryptfs(const char *const path,
                                    const char *const mount_options)
{
        int ret;
        char ecryptfs_sig_hex[ECRYPTFS_SIG_SIZE_HEX + 1];

        /* umount ecryptfs */
        ret = ecryptfs_wait_and_unmount(path);
        if (ret < 0) {
                SLOGE("Error unmounting ecryptfs");
                if (ESS_DEBUG)
                        dump_lsof(path);
                return ret;
        }

        /* get signature for user's key in kernel keychain
         * from mount options read from /proc/mounts */
        ret =
            get_sig_from_mount_options(path, mount_options, ecryptfs_sig_hex);
        if (ret < 0)
                return ret;

        /* delete ecryptfs sig key from kernel keychain */
        ret = remove_tok_from_keyring(ecryptfs_sig_hex);
        if (ret < 0) {
                SLOGE("Error deleting ecryptfs key");
                return ret;
        }

        return 0;
}

/**
 * ARKHAM-30: Unmount ecryptfs from given path.
 * If ecryptfs is mounted on given path, unmount it
 * and retry several times in case of failure.
 * Cleanup kernel keyring.
 */
int ess_unmount_ecryptfs(const char *const path)
{
        int ret = 0;
        char mount_options[MAX_OPTION_LENGTH];

        /* Nothing to do if ecryptfs is not mounted on <path> */
        if (!is_mounted(path, mount_options)) {
                SLOGD("ecryptfs is not mounted on %s\n", path);
                return 0;
        }

        /* umount ecryptfs */
        ret = unmount_mounted_ecryptfs(path, mount_options);
        if (ret < 0)
                return ret;
        return 0;
}

/**
 * ARKHAM-30: Unmount all mounted ecryptfs filesystems.
 * Check /proc/mounts and unmount all found ecrypfs mountpoints.
 */
int ess_unmount_all_ecryptfs(void)
{
        int ret = 0, err = 0;
        char mount_options[MAX_OPTION_LENGTH];
        char device[MAX_OPTION_LENGTH];
        char mount_path[MAX_OPTION_LENGTH];
        char type[MAX_OPTION_LENGTH];
        FILE *fp = NULL;
        char line[MAX_LINE_LENGTH];

        fp = fopen("/proc/mounts", "r");
        if (!fp) {
                SLOGE("Error opening /proc/mounts (%s)", strerror(errno));
                return -1;
        }

        /* Looking for lines that look like:
         * <path> <path> ecryptfs <mount_options>
         * e.g.: /data/user/10 /data/user/10 ecryptfs ...
         */
        while (fgets(line, sizeof(line), fp)) {
                sscanf(line, "%255s %255s %255s %255s", device, mount_path,
                       type, mount_options);

                /* Search for lines with type ecryptfs */
                if (!strncmp(type, "ecryptfs", strlen("ecryptfs")) &&
                    !strncmp(device, mount_path, strlen(device))) {
                        /* umount ecryptfs */
                        ret =
                            unmount_mounted_ecryptfs(mount_path, mount_options);
                        if (ret < 0)
                                err = ret;
                }
        }
        fclose(fp);
        return err;
}

/**
 * ARKHAM-248: Delete a container.
 * This is only used with Chaabi.
 * It deletes any container information saved in Chaabi.
 */
int ess_delete(int cid)
{
        int ret = 0;

#ifdef ENABLE_CHAABI_IN_HW
        ret = cont_sec_delete(cid);
        if (ret != CONT_SUCCESS) {
                SLOGE("Cannot delete container with cid %d (error = 0x%x)\n",
                      cid, ret);
                return -1;
        }
#endif
        return 0;
}

/**
 * ARKHAM-248: Enable a container.
 * This is only used with Chaabi.
 * Marks a container as enabled in Chaabi FW.
 */
int ess_enable(int cid)
{
        int ret = 0;

#ifdef ENABLE_CHAABI_IN_HW
        ret = cont_sec_enable(cid);
        if (ret != CONT_SUCCESS) {
                SLOGE("Cannot enable container with cid %d (error = 0x%x)\n",
                      cid, ret);
                return -1;
        }
#endif
        return 0;
}

/**
 * ARKHAM-248: Disables a container.
 * This is only used with Chaabi.
 * Marks a container as disabled in Chaabi FW.
 */
int ess_disable(int cid)
{
        int ret = 0;

#ifdef ENABLE_CHAABI_IN_HW
        ret = cont_sec_disable(cid);
        if (ret != CONT_SUCCESS) {
                SLOGE("Cannot disable container with cid %d (error = 0x%x)\n",
                      cid, ret);
                return -1;
        }
#endif
        return 0;
}

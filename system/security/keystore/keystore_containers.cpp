/*
 * Copyright (C) 2013
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


static int32_t is_mounted(char * dev_path) {
    FILE *file = fopen("/proc/mounts", "r");
    if (file != NULL) {
        char line[128];
        while (fgets(line, sizeof line, file) != NULL) {
            char dev[64];
            sscanf(line, "%s %*s", dev);
            if ((dev != NULL) && (strcmp(dev, dev_path)) == 0) {
                fclose(file);
                return 1;
            }
        }
        fclose(file);
    } else {
        ALOGE("cannot open /proc/mounts");
    }
    ALOGI("%s is not mounted", dev_path);
    return 0;
}

// Check if speicifed userId is a container one
static bool is_container_user(int32_t user_id) {
    char dev_path[64];
    strcpy(dev_path, "/data/system/users/%d");
    sprintf(dev_path, dev_path, user_id);
    return (is_mounted(dev_path) == 1);
}

static int32_t wipe_container_keystore(int32_t cid) {
    char path[64];
    sprintf(path, "user_%u", cid);

    ALOGI("wipe container keystore: %s", path);

    // Delete keystore dir and all its files
    DIR *dir = opendir(path);
    if (dir == NULL) {
        ALOGE("cannot open keystore dir %s for wiping: %s", path, strerror(errno));
        return SYSTEM_ERROR;;
    }

    struct dirent* file;
    while ((file = readdir(dir)) != NULL) {
        // We only care about files.
        if (file->d_type != DT_REG) {
            continue;
        }

        if (unlinkat(dirfd(dir), file->d_name, 0) && errno != ENOENT) {
            ALOGW("couldn't unlink %s", file->d_name);
        }
    }
    closedir(dir);

    if (rmdir(path)) {
        ALOGW("cannot wipe keystore dir %s for cid %d: %s", path, cid,
              strerror(errno));
        return SYSTEM_ERROR;
    }

    ALOGI("wiping keystore for cid %d successfully completed", cid);
    return NO_ERROR;
}

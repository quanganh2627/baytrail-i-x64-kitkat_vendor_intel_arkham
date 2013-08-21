/**
 * TODO: Add distribution license for this file
 * author: Catalin Ionita<catalin.ionita@intel.com>
 */

package com.intel.arkham;
import java.util.Map;

/**
 * Internal IPC interface to the container policy service.
 * {@hide}
 */
interface IContainerPolicyManager {

        boolean getAllowCopyFromContainer();
        void    setAllowCopyFromContainer(boolean value);

        boolean getAllowCopyIntoContainer();
        void    setAllowCopyIntoContainer(boolean value);

        boolean getExportCalendarAcrossUsers();
        void    setExportCalendarAcrossUsers(boolean value);

        boolean getExportEmailContentAcrossUsers();
        void    setExportEmailContentAcrossUsers(boolean value);

        long    getContainerLockTimeout();
        int     getContainerLockTimeoutType();
        void    setContainerLockTimeout(long value, int type);

        Map     getApplicationWhiteList();
        void    setApplicationWhiteList(in Map appWhiteList);

        List    getSystemBlackList();
        void    setSystemBlackList(in List systemBlackList);

        List    getContactFieldWhiteList();
        void    setContactFieldWhiteList(in List contactFieldWhiteList);

        boolean getAllowCopyFromContainerForContainer(int cid);
        boolean getAllowCopyIntoContainerForContainer(int cid);

        boolean isApplicationWhiteListed(int cid, String pkgName, String pkgVer, String pkgOrigin);
        boolean isApplicationBlackListed(int cid, String pkgName);

        long    getContainerLockTimeoutForContainer(int cid);
        int     getContainerLockTimeoutTypeForContainer(int cid);

        List    getContactFieldWhiteListForContainer(int cid);
}

#!/bin/bash

CIS="cis-ubuntu-linux-18.04"
NO_SEC="\033[1;31m[not secured]\033[0m"
SEC="\033[1;37m[secured]\033[0m"


if modprobe -n -v cramfs | grep -v mtd| grep -oi 'install /bin/true'|wc -l| grep -vq '0' || lsmod|grep cramfs|wc -l| grep -q '0'; then 
printf "\n$CIS 1.1.1.1 Ensure mounting of cramfs filesystems is disabled $SEC\n"
else printf "\n$CIS 1.1.1.1 Ensure mounting of cramfs filesystems is disabled $NO_SEC
Description:The cramfsfilesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfsimage can be used without having to first decompress the image.\n"
fi

if modprobe -n -v freevxfs| grep -oi 'install /bin/true'|wc -l| grep -vq '0' || lsmod | grep freevxfs|wc -l| grep -q '0'; then 
printf "\n$CIS 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled  $SEC\n"
else printf "\n$CIS 1.1.1.1 Ensure mounting of freevxfs filesystems is disabled $NO_SEC
Description:The freevxfsfilesystem type is a free version of the Veritas type filesystem. This is the primary filesystem type for HP-UX operating systems."
fi

if modprobe -n -v jffs2 | grep -v mtd| grep -oi 'install /bin/true'|wc -l| grep -vq '0' || lsmod | grep jffs2|wc -l| grep -q '0'; then 
printf "\n$CIS 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled  $SEC\n"
else printf "\n$CIS 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled $NO_SEC
Description:The jffs2(journaling flash filesystem 2) filesystem type is a log-structured filesystem used in flash memory devices.\n"
fi

if modprobe -n -v hfs| grep -oi 'install /bin/true'|wc -l| grep -vq '0' || lsmod | grep hfs|wc -l| grep -q '0'; then 
printf "\n$CIS 1.1.1.4 Ensure mounting of hfs filesystems is disabled  $SEC\n"
else printf "\n$CIS 1.1.1.4 Ensure mounting of hfs filesystems is disabled $NO_SEC
Description: The hfsfilesystem type is a hierarchical filesystem that allows you to mountMac OS filesystems.\n"
fi

if modprobe -n -v hfsplus| grep -oi 'install /bin/true'|wc -l| grep -vq '0' || lsmod | grep hfsplus|wc -l| grep -q '0'; then 
printf "\n$CIS 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled  $SEC\n"
else printf "\n$CIS 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled $NO_SEC
Description: The hfsplusfilesystem type is a hierarchical filesystem designed to replace hfsthat allows you to mount Mac OS filesystems.\n"
fi

if modprobe --showconfig | grep squashfs| grep -oi 'install /bin/true'|wc -l| grep -vq '0' || lsmod | grep squashfs|wc -l| grep -q '0'; then 
printf "\n$CIS 1.1.1.6 Ensure mounting of squashfs filesystems is disabled  $SEC\n"
else printf "\n$CIS 1.1.1.6 Ensure mounting of squashfs filesystems is disabled $NO_SEC
Description: The squashfsfilesystem type is a compressed read-only Linux filesystem embedded in small footprint systems (similar to cramfs). A squashfsimagecan be used without having to first decompress the image\n"
fi

if modprobe -n -v udf | grep -v crc-itu-t| grep -oi 'install /bin/true'|wc -l| grep -vq '0' || lsmod | grep udf|wc -l| grep -q '0'; then 
printf "\n$CIS 1.1.1.7 Ensure mounting of udf filesystems is disabled   $SEC\n"
else printf "\n$CIS 1.1.1.7 Ensure mounting of udf filesystems is disabled  $NO_SEC
Description: The udffilesystem type is the universal disk format used toimplement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data storage on a broad range of media. This filesystem type is necessary to support writing DVDs and newer optical disc formats.\n"
fi

if modprobe --showconfig | grep vfat| grep -oi 'install /bin/true'|wc -l| grep -vq '0' || lsmod | grep vfat|wc -l| grep -q '0'; then 
printf "\n$CIS 1.1.1.8 Ensure mounting of FAT filesystems is limited   $SEC\n"
else printf "\n$CIS 1.1.1.8 Ensure mounting of FAT filesystems is limited  $NO_SEC
Description: The FATfilesystem format is primarily used on older windows systems and portable USB drives or flash modules. It comes in three types FAT12, FAT16, and FAT32all of which are supported by the vfatkernel module.\n"
fi

if mount | grep -E '\s/tmp\s'| grep -oi "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)"|wc -l| grep -vq '0' || grep -E '\s/tmp\s' /etc/fstab | grep -E -v '^\s*#'|grep -oi 'tmpfs   /tmp tmpfs   defaults,noexec,nosuid,nodev 0   0'|wc -l| grep -vq '0' || systemctl is-enabled tmp.mount|grep -oi 'enabled'|wc -l| grep -vq '0'; then 
printf "\n$CIS 1.1.2 Ensure /tmp is configured   $SEC\n"
else printf "\n$CIS 1.1.2 Ensure /tmp is configured  $NO_SEC
Description: The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.\n"
fi

if mount | grep -E '\s/tmp\s'| wc -l| grep -q '0' ; then 
printf "\n$CIS 1.1.3 Ensure nodev option set on /tmp partition   $SEC\n"
else printf "\n$CIS 1.1.3 Ensure nodev option set on /tmp partition  $NO_SEC
Description: The nodev mount option specifies that the filesystem cannot contain special devices.\n"
fi

if mount | grep -E '\s/tmp\s' | grep -v nosuid| wc -l| grep -q '0' ; then 
printf "\n$CIS 1.1.4 Ensure nosuid option set on /tmp partition    $SEC\n"
else printf "\n$CIS 1.1.4 Ensure nosuid option set on /tmp partition   $NO_SEC
Description: The nosuid mount option specifies that the filesystem cannot contain setuidfiles.\n"
fi

if mount | grep -E '\s/tmp\s' | grep -v noexec| wc -l| grep -q '0' ; then 
printf "\n$CIS 1.1.5 Ensure noexec option set on /tmp partition    $SEC\n"
else printf "\n$CIS 1.1.5 Ensure noexec option set on /tmp partition  $NO_SEC
Description: The noexec mount option specifies that the filesystem cannot contain executable binaries.\n"
fi

if mount | grep -E '\s/var\s'|grep -oi '/dev/xvdg1 on /var type ext4 (rw,relatime,data=ordered)'| wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.1.6 Ensure separate partition exists for /var     $SEC\n"
else printf "\n$CIS 1.1.6 Ensure separate partition exists for /var   $NO_SEC
Description: The /vardirectory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable.\n"
fi

if mount | grep /var/tmp|grep -io 'on /var/tmp type ext4 (rw,nosuid,nodev,noexec,relatime)'| wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.1.7 Ensure separate partition exists for /var/tmp     $SEC\n"
else printf "\n$CIS 1.1.7 Ensure separate partition exists for /var/tmp   $NO_SEC
Description: The /var/tmp directory is a world-writable directory used for temporary storage by all users and some applications.\n"
fi

if mount | grep -E '\s/var/tmp\s' | grep -v nodev| wc -l| grep -q '0' ; then 
printf "\n$CIS 1.1.8 Ensure nodev option set on /var/tmp partition     $SEC\n"
else printf "\n$CIS 1.1.8 Ensure nodev option set on /var/tmp partition   $NO_SEC
Description: Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /var/tmp..\n"
fi


if mount | grep -E '\s/var/tmp\s' | grep -v nosuid| wc -l| grep -q '0' ; then 
printf "\n$CIS 1.1.9 Ensure nosuid option set on /var/tmp partition     $SEC\n"
else printf "\n$CIS 1.1.9 Ensure nosuid option set on /var/tmp partition   $NO_SEC
Description: The nosuid mount option specifies that the filesystem cannot contain setuidfiles..\n"
fi

if mount | grep -E '\s/var/tmp\s' | grep -v noexec| wc -l| grep -q '0' ; then 
printf "\n$CIS 1.1.10 Ensure noexec option set on /var/tmp partition     $SEC\n"
else printf "\n$CIS 1.1.10 Ensure noexec option set on /var/tmp partition   $NO_SEC
Description: The noexec mount option specifies that the filesystem cannot contain executable binaries.\n"
fi






if grep "^\s*linux" /boot/grub/grub.cfg | grep -v "ipv6.disable=1"|wc -l| grep -q '0'; then
printf "\n$CIS 3.7 Disable IPv6 $SEC\n"
else printf "\n$CIS 3.7 Disable IPv6 $NO_SEC
Description:Although IPv6 has many advantages over IPv4, not all organizations have IPv6 or dual stack configurations implemented.Rationale:If IPv6 or dual stack is not to be used, it is recommended that IPv6 be disabled to reduce the attack surface of the system.\n"
fi

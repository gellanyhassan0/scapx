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

if mount | grep /var/log|grep -io '/dev/xvdh1 on /var/log type ext4 (rw,relatime,data=ordered)'| wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.1.11 Ensure separate partition exists for /var/log     $SEC\n"
else printf "\n$CIS 1.1.11 Ensure separate partition exists for /var/log   $NO_SEC
Description: The /var/log directory is used by system services to store log data .\n"
fi

if mount | grep /var/log/audit|grep -io '/dev/xvdi1 on /var/log/audit type ext4 (rw,relatime,data=ordered)'| wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.1.12 Ensure separate partition exists for /var/log/audit     $SEC\n"
else printf "\n$CIS 1.1.12 Ensure separate partition exists for /var/log/audit   $NO_SEC
Description: The auditing daemon, auditd, stores log data in the /var/log/auditdirectory.\n"
fi

if mount | grep /home|grep -io '/dev/xvdf1 on /home type ext4 (rw,nodev,relatime,data=ordered)'| wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.1.13 Ensure separate partition exists for /home     $SEC\n"
else printf "\n$CIS 1.1.13 Ensure separate partition exists for /home   $NO_SEC
Description: The /home directory is used to support disk storage needs of local users.\n"
fi

if mount | grep -E '\s/home\s' | grep -v nodev| wc -l| grep -q '0' ; then 
printf "\n$CIS 1.1.14 Ensure nodev option set on /home partition      $SEC\n"
else printf "\n$CIS 1.1.14 Ensure nodev option set on /home partition    $NO_SEC
Description: The nodev mount option specifies that the filesystem cannot contain special devices.\n"
fi

if mount | grep -E '\s/dev/shm\s' | grep -v nodev| wc -l| grep -q '0' ; then 
printf "\n$CIS 1.1.15 Ensure nodev option set on /dev/shm partition      $SEC\n"
else printf "\n$CIS 1.1.15 Ensure nodev option set on /dev/shm partition    $NO_SEC
Description: The nodev mount option specifies that the filesystem cannot contain special devices.\n"
fi

if mount | grep -E '\s/dev/shm\s' | grep -v nosuid| wc -l| grep -q '0' ; then 
printf "\n$CIS 1.1.16 Ensure nosuid option set on /dev/shm partition       $SEC\n"
else printf "\n$CIS 1.1.16 Ensure nosuid option set on /dev/shm partition     $NO_SEC
Description: The nosuid mount option specifies that the filesystem cannot contain setuid files.\n"
fi

if mount | grep -E '\s/dev/shm\s' | grep -v noexec| wc -l| grep -q '0' ; then 
printf "\n$CIS 1.1.17 Ensure noexec option set on /dev/shm partition       $SEC\n"
else printf "\n$CIS 1.1.17 Ensure noexec option set on /dev/shm partition     $NO_SEC
Description: The noexec mount option specifies that the filesystem cannot contain executable binaries.\n"
fi

if mount|grep -i "nodev"| wc -l| grep -vq '0' && mount|grep -i "nosuid"| wc -l| grep -vq '0' && mount|grep -i "noexec"| wc -l| grep -vq '0'; then 
printf "\n$CIS 1.1.(18|19|20) Ensure nodev option set on removable media partitions       $SEC\n"
else printf "\n$CIS 1.1.(18|19|20) Ensure nodev option set on removable media partitions     $NO_SEC
Description: The nodev mount option specifies that the filesystem cannot contain special devices.
The nosuid mount option specifies that the filesystem cannot contain setuid files.
The noexec mount option specifies that the filesystem cannot contain executable binaries.\n"
fi

if  systemctl is-enabled autofs|grep -io 'disabled'| wc -l| grep -vq '0' || dpkg -s autofs|grep -io 'package `autofs` is not installed'| wc -l| grep -vq '0'; then 
printf "\n$CIS 1.1.22 Disable Automounting       $SEC\n"
else printf "\n$CIS 1.1.22 Disable Automounting     $NO_SEC
Description: autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.\n"
fi

if  modprobe -n -v usb-storage|grep -io 'install /bin/true'| wc -l| grep -vq '0' || lsmod | grep usb-storage|wc -l| grep -q '0'; then 
printf "\n$CIS 1.1.23 Disable USB Storage        $SEC\n"
else printf "\n$CIS 1.1.23 Disable USB Storage      $NO_SEC
Description: USB storage provides a means to transfer and store files insuring persistence and
availability of the files independent of network connection status. Its popularity and utility
has led to USB-based malware being a simple and common means for network infiltration
and a first step to establishing a persistent threat within a networked environment.\n"
fi

if dpkg -s sudo|grep -io 'Status: install ok installed'| wc -l| grep -vq '0' || dpkg -s sudo-ldap|grep -io 'Status: install ok installed'| wc -l| grep -vq '0'; then 
printf "\n$CIS 1.3.1 Ensure sudo is installed       $SEC\n"
else printf "\n$CIS 1.3.1 Ensure sudo is installed     $NO_SEC
Description: sudo allows a permitted user to execute a command as the superuser or another user, as
specified by the security policy. The invoking user's real (not effective) user ID is used to
determine the user name with which to query the security policy.\n"
fi

if   grep -Ei '^\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$' /etc/sudoers /etc/sudoers.d/*|grep -io 'Defaults use_pty'| wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.3.2 Ensure sudo commands use pty        $SEC\n"
else printf "\n$CIS 1.3.2 Ensure sudo commands use pty      $NO_SEC
Description: sudo can be configured to run only from a psuedo-pty.\n"
fi

if  grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/*|grep -io 'Defaults logfile='| wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.3.3 Ensure sudo log file exists       $SEC\n"
else printf "\n$CIS 1.3.3 Ensure sudo log file exists     $NO_SEC
Description: sudo can use a custom log file.\n"
fi

if  stat /boot/grub/grub.cfg|grep -io 'Access: (0400/-r--------)'| wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.5.1 Ensure permissions on bootloader config are configured       $SEC\n"
else printf "\n$CIS 1.5.1 Ensure permissions on bootloader config are configured     $NO_SEC
Description: The grub configuration file contains information on boot settings and passwords for
unlocking boot options. The grub configuration is usually grub.cfg stored in /boot/grub/.\n"
fi

if   grep "^set superusers" /boot/grub/grub.cfg|grep -io 'set superusers='| wc -l| grep -vq '0'||grep "^password" /boot/grub/grub.cfg|grep -io 'password_pbkdf2'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.5.2 Ensure bootloader password is set       $SEC\n"
else printf "\n$CIS 1.5.2 Ensure bootloader password is set     $NO_SEC
Description: Setting the boot loader password will require that anyone rebooting the system must enter
a password before being able to set command line boot parameters.\n"
fi

if  grep '^root:[*\!]:' /etc/shadow|grep -i 'root'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.5.3 Ensure authentication required for single user mode       $SEC\n"
else printf "\n$CIS 1.5.3 Ensure authentication required for single user mode     $NO_SEC
Description: Single user mode is used for recovery when the system detects an issue during boot or by
manual selection from the bootloader.\n"
fi

if   grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot|grep -oi 'PROMPT_FOR_CONFIRM="no"'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.5.4 Ensure interactive boot is not enabled       $SEC\n"
else printf "\n$CIS 1.5.4 Ensure interactive boot is not enabled     $NO_SEC
Description: Interactive boot allows console users to interactively select which services start on boot.
Not all distributions support this capability.
The PROMPT_FOR_CONFIRM option provides console users the ability to interactively boot the
system and select which services to start on boot .\n"
fi

if  journalctl | grep 'protection: active'|grep -io 'kernel: NX (Execute Disable) protection: active'| wc -l| grep -vq '0' ||[[ -n $(grep noexec[0-9]*=off /proc/cmdline) || -z $(grep -E -i ' (pae|nx)
' /proc/cpuinfo) || -n $(grep '\sNX\s.*\sprotection:\s' /var/log/dmesg | grep
-v active) ]] && echo "NX Protection is not active"|wc -l| grep -q '0'; then 
printf "\n$CIS 1.6.1 Ensure XD/NX support is enabled        $SEC\n"
else printf "\n$CIS 1.6.1 Ensure XD/NX support is enabled      $NO_SEC
Description: Recent processors in the x86 family support the ability to prevent code execution on a per
memory page basis. Generically and on AMD processors, this ability is called No Execute
(NX), while on Intel processors it is called Execute Disable (XD). This ability can help
prevent exploitation of buffer overflow vulnerabilities and should be activated whenever
possible. Extra steps must be taken to ensure that this protection is enabled, particularly on
32-bit x86 systems. Other processors, such as Itanium and POWER, have included such
support since inception and the standard kernel for those platforms supports the feature.\n"
fi

if  sysctl kernel.randomize_va_space|grep -oi 'kernel.randomize_va_space = 2'|wc -l| grep -vq '0' || grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*|grep -io 'kernel.randomize_va_space = 2'|wc -l| grep -vq '0'; then 
printf "\n$CIS 1.6.2 Ensure address space layout randomization (ASLR) is enabled       $SEC\n"
else printf "\n$CIS 1.6.2 Ensure address space layout randomization (ASLR) is enabled     $NO_SEC
Description: Address space layout randomization (ASLR) is an exploit mitigation technique which
randomly arranges the address space of key data areas of a process.\n"
fi

if  dpkg -s prelink|grep -oi 'not installed'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.6.3 Ensure prelink is disabled       $SEC\n"
else printf "\n$CIS 1.6.3 Ensure prelink is disabled     $NO_SEC
Description: prelinkis a program that modifies ELF shared libraries and ELF dynamically linked
binaries in such a way that the time needed for the dynamic linker to perform relocations
at startup significantly decreases.\n"
fi

if  grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*|grep -oi '* hard core 0'|wc -l| grep -vq '0' || sysctl fs.suid_dumpable|grep -io 'fs.suid_dumpable = 0
'|wc -l| grep -vq '0'|grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*|grep -io 'fs.suid_dumpable = 0'|wc -l| grep -vq '0'||systemctl is-enabled coredump.service|grep -io 'enabled\|disabled'|wc -l| grep -vq '0'; then 
printf "\n$CIS 1.6.4 Ensure core dumps are restricted       $SEC\n"
else printf "\n$CIS 1.6.4 Ensure core dumps are restricted     $NO_SEC
Description: A core dump is the memory of an executable program. It is generally used to determine
why a program aborted. It can also be used to glean confidential information from a core
file. The system provides the ability to set a soft limit for core dumps, but this can be
overridden by the user.\n"
fi

if  dpkg -s apparmor apparmor-utils|grep -oi 'Status: install ok installed'|wc -l| grep -vq '0' || apparmor_status|grep -io 'apparmor module is loaded'|wc -l|grep -vq '0' ; then 
printf "\n$CIS 1.7.1.(1|4) Ensure AppArmor is installed      $SEC\n"
else printf "\n$CIS 1.7.1.(1|4) Ensure AppArmor is installed     $NO_SEC
Description: AppArmor provides Mandatory Access Controls.
AppArmor profiles define what resources applications are able to access.\n"
fi

if grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1" | grep -v '/boot/memtest86+.bin'|wc -l| grep -q '0' || grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor" | grep -v '/boot/memtest86+.bin'|wc -l| grep -q '0'; then 
printf "\n$CIS 1.7.1.2 Ensure AppArmor is enabled in the bootloader configuration      $SEC\n"
else printf "\n$CIS 1.7.1.2 Ensure AppArmor is enabled in the bootloader configuration     $NO_SEC
Description: Configure AppArmor to be enabled at boot time and verify that it has not been overwritten
by the bootloader boot parameters..\n"
fi


if  apparmor_status | grep -oi 'profiles\|processes'|grep -io 'profiles are loaded\| processes have profiles defined'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 1.7.1.3 Ensure all AppArmor Profiles are in enforce or complain mode      $SEC\n"
else printf "\n$CIS 1.7.1.3 Ensure all AppArmor Profiles are in enforce or complain mode     $NO_SEC
Description: AppArmor profiles define what resources applications are able to access..\n"
fi




if  systemctl is-enabled systemd-timesyncd|grep -oi 'enabled'|wc -l| grep -vq '0' || dpkg -s chrony|grep -io 'Status: install ok installed'|wc -l|grep -vq '0'|| dpkg -s ntp|grep -io 'Status: install ok installed'|wc -l|grep -vq '0'|| timedatectl status|grep -io 'System clock synchronized:\|NTP enabled:'|wc -l|grep -vq '0'; then 
printf "\n$CIS 2.2.1.(1|2) Ensure time (synchronization|configured) is in use       $SEC\n"
else printf "\n$CIS 2.2.1.(1|2) Ensure time (synchronization|configured) is in use     $NO_SEC
Description:System time should be synchronized between all systems in an environment. This is
typically done by establishing an authoritative time server or set of servers and having all
systems synchronize their clocks to them.\n"
fi


if  systemctl is-enabled avahi-daemon 2>&1|grep -oi 'enable'|wc -l|grep -q '0'; then 
printf "\n$CIS 2.2.3 Ensure Avahi Server is not enabled       $SEC\n"
else printf "\n$CIS 2.2.3 Ensure Avahi Server is not enabled     $NO_SEC
Description: Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD
service discovery. Avahi allows programs to publish and discover services and hosts
running on a local network with no specific configuration. For example, a user can plug a
computer into a network and Avahi automatically finds printers to print to, files to look at
and people to talk to, as well as network services running on the machine.\n"
fi

if  systemctl is-enabled cups 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.4 Ensure CUPS is not enabled       $SEC\n"
else printf "\n$CIS 2.2.4 Ensure CUPS is not enabled     $NO_SEC
Description: The Common Unix Print System (CUPS) provides the ability to print to both local and
network printers. A system running CUPS can also accept print jobs from remote systems
and print them to local printers. It also provides a web based remote administration
capability.\n"
fi

if  systemctl is-enabled slapd 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.6 Ensure LDAP server is not enabled       $SEC\n"
else printf "\n$CIS 2.2.6 Ensure LDAP server is not enabled     $NO_SEC
Description: The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for
NIS/YP. It is a service that provides a method for looking up information from a central
database.\n"
fi

if  systemctl is-enabled nfs-server 2>&1|grep -oi 'enable'|wc -l|grep -q '0' || systemctl is-enabled rpcbind|grep -oi 'enable'|wc -l|grep -q '0'; then 
printf "\n$CIS 2.2.7 Ensure NFS and RPC are not enabled       $SEC\n"
else printf "\n$CIS 2.2.7 Ensure NFS and RPC are not enabled     $NO_SEC
Description: The Network File System (NFS) is one of the first and most widely distributed file systems
in the UNIX environment. It provides the ability for systems to mount file systems of other
servers through the network.\n"
fi

if  systemctl is-enabled bind9 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.8 Ensure DNS Server is not enabled       $SEC\n"
else printf "\n$CIS 2.2.8 Ensure DNS Server is not enabled     $NO_SEC
Description: The Domain Name System (DNS) is a hierarchical naming system that maps names to IP
addresses for computers, services and other resources connected to a network.\n"
fi

if  systemctl is-enabled vsftpd 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.9 Ensure FTP Server is not enabled       $SEC\n"
else printf "\n$CIS 2.2.9 Ensure FTP Server is not enabled     $NO_SEC
Description: The File Transfer Protocol (FTP) provides networked computers with the ability to transfer
files.\n"
fi

if  systemctl is-enabled apache2 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.10 Ensure HTTP server is not enabled        $SEC\n"
else printf "\n$CIS 2.2.10 Ensure HTTP server is not enabled      $NO_SEC
Description: HTTP or web servers provide the ability to host web site content.\n"
fi











if grep "^\s*linux" /boot/grub/grub.cfg | grep -v "ipv6.disable=1"|wc -l| grep -q '0'; then
printf "\n$CIS 3.7 Disable IPv6 $SEC\n"
else printf "\n$CIS 3.7 Disable IPv6 $NO_SEC
Description:Although IPv6 has many advantages over IPv4, not all organizations have IPv6 or dual stack configurations implemented.Rationale:If IPv6 or dual stack is not to be used, it is recommended that IPv6 be disabled to reduce the attack surface of the system.\n"
fi

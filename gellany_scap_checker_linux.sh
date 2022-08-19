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

if mount|grep -i "nodev"| wc -l| grep -vq '0' || mount|grep -i "nosuid"| wc -l| grep -vq '0' || mount|grep -i "noexec"| wc -l| grep -vq '0'; then 
printf "\n$CIS 1.1.(18|19|20) Ensure nodev option set on removable media partitions       $SEC\n"
else printf "\n$CIS 1.1.(18|19|20) Ensure nodev option set on removable media partitions     $NO_SEC
Description: The nodev mount option specifies that the filesystem cannot contain special devices.
The nosuid mount option specifies that the filesystem cannot contain setuid files.
The noexec mount option specifies that the filesystem cannot contain executable binaries.\n"
fi

if  systemctl is-enabled autofs|grep -io 'disabled'| wc -l| grep -vq '0' || dpkg -s autofs 2>&1|grep -io 'package `autofs` is not installed'| wc -l| grep -vq '0'; then 
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

if dpkg -s sudo 2>&1|grep -io 'Status: install ok installed'| wc -l| grep -vq '0' || dpkg -s sudo-ldap 2>&1|grep -io 'Status: install ok installed'| wc -l| grep -vq '0'; then 
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
-v active) ]] || echo "NX Protection is not active"|wc -l| grep -q '0'; then 
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

if  dpkg -s prelink 2>&1|grep -oi 'not installed'|wc -l| grep -vq '0' ; then 
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

if  dpkg -s apparmor apparmor-utils 2>&1|grep -oi 'Status: install ok installed'|wc -l| grep -vq '0' || apparmor_status|grep -io 'apparmor module is loaded'|wc -l|grep -vq '0' ; then 
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




if  systemctl is-enabled systemd-timesyncd|grep -oi 'enabled'|wc -l| grep -vq '0' || dpkg -s chrony 2>&1|grep -io 'Status: install ok installed'|wc -l|grep -vq '0'|| dpkg -s ntp 2>&1|grep -io 'Status: install ok installed'|wc -l|grep -vq '0'|| timedatectl status|grep -io 'System clock synchronized:\|NTP enabled:'|wc -l|grep -vq '0'; then 
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

if  systemctl is-enabled slapd 2>&1|grep -oi 'enable'|wc -l|grep -q '0' || dpkg -s ldap-utils 2>&1 |grep -oi 'not installed'|wc -l| grep -vq '0' ; then 
printf "\n$CIS (2.2.6|2.3.5) Ensure LDAP server is not enabled       $SEC\n"
else printf "\n$CIS (2.2.6|2.3.5) Ensure LDAP server is not enabled     $NO_SEC
Description: The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for
NIS/YP. It is a service that provides a method for looking up information from a central
database.\n"
fi

if  systemctl is-enabled nfs-server 2>&1|grep -oi 'enable'|wc -l|grep -q '0' || systemctl is-enabled rpcbind|grep -oi 'enable'|wc -l|grep -q '0'; then 
printf "\n$CIS 2.2.7 Ensure NFS and RPC are not enabled  $SEC\n"
else printf "\n$CIS 2.2.7 Ensure NFS and RPC are not enabled  $NO_SEC
Description: The Network File System (NFS) is one of the first and most widely distributed file systems
in the UNIX environment. It provides the ability for systems to mount file systems of other
servers through the network.\n"
fi

if  systemctl is-enabled bind9 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.8 Ensure DNS Server is not enabled  $SEC\n"
else printf "\n$CIS 2.2.8 Ensure DNS Server is not enabled  $NO_SEC
Description: The Domain Name System (DNS) is a hierarchical naming system that maps names to IP
addresses for computers, services and other resources connected to a network.\n"
fi

if  systemctl is-enabled vsftpd 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.9 Ensure FTP Server is not enabled  $SEC\n"
else printf "\n$CIS 2.2.9 Ensure FTP Server is not enabled  $NO_SEC
Description: The File Transfer Protocol (FTP) provides networked computers with the ability to transfer
files.\n"
fi

if  systemctl is-enabled apache2 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.10 Ensure HTTP server is not enabled  $SEC\n"
else printf "\n$CIS 2.2.10 Ensure HTTP server is not enabled  $NO_SEC
Description: HTTP or web servers provide the ability to host web site content.\n"
fi

if  systemctl is-enabled dovecot 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.11 Ensure email services are not enabled  $SEC\n"
else printf "\n$CIS 2.2.11 Ensure email services are not enabled  $NO_SEC
Description: dovecot is an open source mail submission and transport server for Linux based systems.\n"
fi

if  systemctl is-enabled smbd 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.12 Ensure Samba is not enabled  $SEC\n"
else printf "\n$CIS 2.2.12 Ensure Samba is not enabled  $NO_SEC
Description: The Samba daemon allows system administrators to configure their Linux systems to share
file systems and directories with Windows desktops. Samba will advertise the file systems
and directories via the Server Message Block (SMB) protocol. Windows desktop users will
be able to mount these directories and file systems as letter drives on their systems.\n"
fi

if  systemctl is-enabled squid 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.13 Ensure HTTP Proxy Server is not enabled  $SEC\n"
else printf "\n$CIS 2.2.13 Ensure HTTP Proxy Server is not enabled  $NO_SEC
Description: Squid is a standard proxy server used in many distributions and environments.\n"
fi

if  systemctl is-enabled snmpd 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.14 Ensure SNMP Server is not enabled  $SEC\n"
else printf "\n$CIS 2.2.14 Ensure SNMP Server is not enabled  $NO_SEC
Description: The Simple Network Management Protocol (SNMP) server is used to listen for SNMP
commands from an SNMP management system, execute the commands or collect the
information and then send results back to the requesting system.\n"
fi

if   ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.15 Ensure mail transfer agent is configured for local-only mode  $SEC\n"
else printf "\n$CIS 2.2.15 Ensure mail transfer agent is configured for local-only mode  $NO_SEC
Description: Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming
mail and transfer the messages to the appropriate user or mail server. If the system is not
intended to be a mail server, it is recommended that the MTA be configured to only process
local mail.\n"
fi

if  systemctl is-enabled rsync 2>&1|grep -oi 'enable'|wc -l|grep -q '0' ; then 
printf "\n$CIS 2.2.16 Ensure rsync service is not enabled   $SEC\n"
else printf "\n$CIS 2.2.16 Ensure rsync service is not enabled   $NO_SEC
Description: The rsyncd service can be used to synchronize files between systems over network links.\n"
fi

if  systemctl is-enabled nis 2>&1|grep -oi 'enable'|wc -l|grep -q '0' || dpkg -s nis 2>&1|grep -oi 'not installed'|wc -l| grep -vq '0' ; then 
printf "\n$CIS (2.2.17|2.3.1) Ensure NIS Server is not enabled   $SEC\n"
else printf "\n$CIS (2.2.17|2.3.1) Ensure NIS Server is not enabled   $NO_SEC
Description: The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server
directory service protocol for distributing system configuration files. The NIS server is a
collection of programs that allow for the distribution of configuration files.\n"
fi

if  dpkg -s rsh-client 2>&1|grep -oi 'not installed'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 2.3.2 Ensure rsh client is not installed   $SEC\n"
else printf "\n$CIS 2.3.2 Ensure rsh client is not installed   $NO_SEC
Description: The rsh package contains the client commands for the rsh services.\n"
fi

if  dpkg -s talk 2>&1|grep -oi 'not installed'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 2.3.3 Ensure talk client is not installed   $SEC\n"
else printf "\n$CIS 2.3.3 Ensure talk client is not installed   $NO_SEC
Description: The talk software makes it possible for users to send and receive messages across systems
through a terminal session. The talk client, which allows initialization of talk sessions, is
installed by default.\n"
fi

if  dpkg -s telnet 2>&1|grep -oi 'not installed'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 2.3.4 Ensure telnet client is not installed    $SEC\n"
else printf "\n$CIS 2.3.4 Ensure telnet client is not installed    $NO_SEC
Description: The telnet package contains the telnet client, which allows users to start connections to
other systems via the telnet protocol.\n"
fi

if  sysctl net.ipv4.conf.all.send_redirects 2>&1|grep -oi 'net.ipv4.conf.all.send_redirects = 0'|wc -l| grep -vq '0' || sysctl net.ipv4.conf.default.send_redirects 2>&1|grep -io 'net.ipv4.conf.default.send_redirects = 0'|wc -l| grep -vq '0' ||  grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.all.send_redirects = 0'|wc -l| grep -vq '0' || grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.default.send_redirects= 0'|wc -l| grep -vq '0'; then 
printf "\n$CIS 3.1.1 Ensure packet redirect sending is disabled     $SEC\n"
else printf "\n$CIS 3.1.1 Ensure packet redirect sending is disabled     $NO_SEC
Description: ICMP Redirects are used to send routing information to other hosts. As a host itself does
not act as a router (in a host only configuration), there is no need to send redirects..\n"
fi

if  sysctl net.ipv4.ip_forward 2>&1|grep -io 'net.ipv4.ip_forward = 0'| wc -l| grep -vq '0' || grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf 2>&1|wc -l| grep -q '0'|sysctl net.ipv6.conf.all.forwarding 2>&1|grep -io 'net.ipv6.conf.all.forwarding = 0'|wc -l| grep -vq '0'| grep -E -s "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf 2>&1|wc -l| grep -q '0' ; then 
printf "\n$CIS 3.1.2 Ensure IP forwarding is disabled    $SEC\n"
else printf "\n$CIS 3.1.2 Ensure IP forwarding is disabled     $NO_SEC
Description: The net.ipv4.ip_forward and net.ipv6.conf.all.forwarding flags are used to tell the
system whether it can forward packets or not.\n"
fi

if  sysctl net.ipv4.conf.all.accept_source_route 2>&1|grep -oi 'sysctl net.ipv4.conf.all.accept_source_route'|wc -l| grep -vq '0' ||  sysctl net.ipv4.conf.default.accept_source_route 2>&1|grep -oi 'net.ipv4.conf.default.accept_source_route = 0'|wc -l| grep -vq '0'|| grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.all.accept_source_route= 0' ||  grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.default.accept_source_route= 0'|wc -l| grep -vq '0'|| sysctl net.ipv6.conf.all.accept_source_route 2>&1|grep -io 'net.ipv6.conf.all.accept_source_route = 0'|wc -l| grep -vq '0'|| sysctl net.ipv6.conf.default.accept_source_route 2>&1|grep -io 'net.ipv6.conf.default.accept_source_route = 0'|wc -l| grep -vq '0'|| grep "net\.ipv6\.conf\.all\.accept_source_route" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.all.accept_source_route= 0'|wc -l| grep -vq '0'||  grep "net\.ipv6\.conf\.default\.accept_source_route" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv6.conf.default.accept_source_route= 0'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 3.2.1 Ensure source routed packets are not accepted    $SEC\n"
else printf "\n$CIS 3.2.1 Ensure source routed packets are not accepted    $NO_SEC
Description: In networking, source routing allows a sender to partially or fully specify the route packets
take through a network. In contrast, non-source routed packets travel a path determined
by routers in the network. In some cases, systems may not be routable or reachable from
some locations (e.g. private addresses vs. Internet routable), and so source routed packets
would need to be used.\n"
fi

if  sysctl net.ipv4.conf.all.accept_redirects 2>&1|grep -oi 'net.ipv4.conf.all.accept_redirects = 0'|wc -l| grep -vq '0'||  sysctl net.ipv4.conf.default.accept_redirects 2>&1|grep -io 'net.ipv4.conf.default.accept_redirects = 0'|wc -l| grep -vq '0'|| grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.all.accept_redirects= 0'|wc -l| grep -vq '0'||grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.default.accept_redirects= 0'|wc -l| grep -vq '0'||sysctl net.ipv6.conf.all.accept_redirects 2>&1|grep -io 'net.ipv6.conf.all.accept_redirects = 0'|wc -l| grep -vq '0'|| sysctl net.ipv6.conf.default.accept_redirects 2>&1|grep -io 'net.ipv6.conf.default.accept_redirects = 0'|wc -l| grep -vq '0'|| grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv6.conf.all.accept_redirects= 0'|wc -l| grep -vq '0'||  grep "net\.ipv6\.conf\.default\.accept_redirects" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv6.conf.default.accept_redirects= 0'|wc -l| grep -vq '0'; then 
printf "\n$CIS 3.2.2 Ensure ICMP redirects are not accepted   $SEC\n"
else printf "\n$CIS 3.2.2 Ensure ICMP redirects are not accepted    $NO_SEC
Description: ICMP redirect messages are packets that convey routing information and tell your host
(acting as a router) to send packets via an alternate path. It is a way of allowing an outside
routing device to update your system routing tables. By setting
net.ipv4.conf.all.accept_redirects and net.ipv6.conf.all.accept_redirects to 0,
the system will not accept any ICMP redirect messages, and therefore, won't allow
outsiders to update the system's routing tables.\n"
fi

if  sysctl net.ipv4.conf.all..secure_redirects 2>&1|grep -oi 'net.ipv4.conf.all.secure_redirects = 0'|wc -l| grep -vq '0'||  sysctl net.ipv4.conf.default.secure_redirects 2>&1|grep -io 'net.ipv4.conf.default.secure_redirects = 0'|wc -l| grep -vq '0'|| grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.all.secure_redirects= 0'|wc -l| grep -vq '0'||grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.default.secure_redirects= 0'|wc -l| grep -vq '0'||sysctl net.ipv6.conf.all.secure_redirects 2>&1|grep -io 'net.ipv6.conf.all.secure_redirects = 0'|wc -l| grep -vq '0'|| sysctl net.ipv6.conf.default.accept_redirects 2>&1|grep -io 'net.ipv6.conf.default.secure_redirects = 0'|wc -l| grep -vq '0'|| grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv6.conf.all.secure_redirects= 0'|wc -l| grep -vq '0'||  grep "net\.ipv6\.conf\.default\.secure_redirects" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv6.conf.default.secure_redirects= 0'|wc -l| grep -vq '0'; then 
printf "\n$CIS 3.2.3 Ensure secure ICMP redirects are not accepted   $SEC\n"
else printf "\n$CIS 3.2.3 Ensure secure ICMP redirects are not accepted    $NO_SEC
Description: Secure ICMP redirects are the same as ICMP redirects, except they come from gateways
listed on the default gateway list. It is assumed that these gateways are known to your
system, and that they are likely to be secure.\n"
fi

if  sysctl net.ipv4.conf.all.log_martians 2>&1|grep -oi 'net.ipv4.conf.all.log_martians = 1'|wc -l| grep -vq '0' || sysctl net.ipv4.conf.default.log_martians 2>&1|grep -io 'net.ipv4.conf.default.log_martians = 1'|wc -l| grep -vq '0'||  grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.all.log_martians = 1'|wc -l| grep -vq '0'|| grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.default.log_martians = 1'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 3.2.4 Ensure suspicious packets are logged    $SEC\n"
else printf "\n$CIS 3.2.4 Ensure suspicious packets are logged    $NO_SEC
Description: When enabled, this feature logs packets with un-routable source addresses to the kernel log.\n"
fi

if   sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>&1|grep -oi 'net.ipv4.icmp_echo_ignore_broadcasts = 1'|wc -l| grep -vq '0' ||  grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.icmp_echo_ignore_broadcasts = 1'|wc -l| grep -vq '0'; then 
printf "\n$CIS 3.2.5 Ensure broadcast ICMP requests are ignored    $SEC\n"
else printf "\n$CIS 3.2.5 Ensure broadcast ICMP requests are ignored    $NO_SEC
Description: Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all
ICMP echo and timestamp requests to broadcast and multicast addresses.\n"
fi

if  sysctl net.ipv4.icmp_ignore_bogus_error_responses 2>&1|grep -oi 'net.ipv4.icmp_ignore_bogus_error_responses = 1'|wc -l| grep -vq '0' ||   grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf/etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.icmp_ignore_bogus_error_responses = 1'|wc -l| grep -vq '0'; then 
printf "\n$CIS 3.2.6 Ensure bogus ICMP responses are ignored    $SEC\n"
else printf "\n$CIS 3.2.6 Ensure bogus ICMP responses are ignored    $NO_SEC
Description: Setting icmp_ignore_bogus_error_responses to 1 prevents the kernel from logging bogus
responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from
filling up with useless log messages.\n"
fi

if  sysctl net.ipv4.conf.all.rp_filter 2>&1|grep -oi 'net.ipv4.conf.all.rp_filter = 1'|wc -l| grep -vq '0' ||  sysctl net.ipv4.conf.default.rp_filter 2>&1|grep -io 'net.ipv4.conf.default.rp_filter = 1'|wc -l| grep -vq '0' || grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.all.rp_filter = 1'|wc -l| grep -vq '0' ||  grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.conf.default.rp_filter = 1'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 3.2.7 Ensure Reverse Path Filtering is enabled    $SEC\n"
else printf "\n$CIS 3.2.7 Ensure Reverse Path Filtering is enabled    $NO_SEC
Description: Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to 1 forces
the Linux kernel to utilize reverse path filtering on a received packet to determine if the
packet was valid. Essentially, with reverse path filtering, if the return packet does not go
out the same interface that the corresponding source packet came from, the packet is
dropped (and logged if log_martians is set).\n"
fi


if  sysctl net.ipv4.tcp_syncookies 2>&1|grep -oi 'net.ipv4.tcp_syncookies = 1'|wc -l| grep -vq '0' || grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/* 2>&1|grep -io 'net.ipv4.tcp_syncookies = 1'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 3.2.8 Ensure TCP SYN Cookies is enabled    $SEC\n"
else printf "\n$CIS 3.2.8 Ensure TCP SYN Cookies is enabled    $NO_SEC
Description: When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the
half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN
cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the
SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that
encodes the source and destination IP address and port number and the time the packet
was sent. A legitimate connection would send the ACK packet of the three way handshake
with the specially crafted sequence number. This allows the system to verify that it has
received a valid response to a SYN cookie and allow the connection, even though there is no
corresponding SYN in the queue.\n"
fi

if sysctl net.ipv6.conf.all.accept_ra 2>&1|grep -oi 'net.ipv6.conf.all.accept_ra = 0'|wc -l| grep -vq '0' || sysctl net.ipv6.conf.default.accept_ra 2>&1|grep -io 'net.ipv6.conf.default.accept_ra = 0'|wc -l| grep -vq '0' ||  grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/* 2>&1|grep -io 'net.ipv6.conf.all.accept_ra = 0'|wc -l| grep -vq '0'||  grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/* 2>&1|grep -io 'net.ipv6.conf.default.accept_ra = 0'; then 
printf "\n$CIS 3.2.9 Ensure IPv6 router advertisements are not accepted    $SEC\n"
else printf "\n$CIS 3.2.9 Ensure IPv6 router advertisements are not accepted    $NO_SEC
Description: This setting disables the system's ability to accept IPv6 router advertisements..\n"
fi

if  dpkg -s ufw | grep -i status 2>&1|grep -oi 'Status: install ok installed'|wc -l| grep -vq '0' || dpkg -s nftables | grep -i status 2>&1|grep -io 'Status: install ok installed'|wc -l| grep -vq '0'|| dpkg -s iptables | grep -i status 2>&1|grep -io 'Status: install ok installed'|wc -l| grep -vq '0' && systemctl is-enabled ufw 2>&1|grep -io 'enabled'|wc -l| grep -vq '0' &&  ufw status | grep Status|grep -io 'Status: active'|wc -l| grep -vq '0'   ; then 
printf "\n$CIS (3.5.1.1|3.5.2.1) Ensure a Firewall package is installed   $SEC\n"
else printf "\n$CIS (3.5.1.1|3.5.2.1) Ensure a Firewall package is installed   $NO_SEC
Description: A Firewall package should be selected. Most firewall configuration utilities operate as a
front end to nftables or iptables.\n"
fi

if   awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>&1|grep -oi '1000'|wc -l| grep -vq '0' &&  dpkg -s rsyslog 2>&1|grep -io 'Status: install ok installed'|wc -l| grep -vq '0' &&  systemctl is-enabled rsyslog 2>&1|grep -io 'enabled'|wc -l| grep -vq '0' &&  grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>&1|grep -io '$FileCreateMode 0640'|wc -l| grep -vq '0' ; then 
printf "\n$CIS (4.1.10|4.2.1.1|4.2.1.2|4.2.1.4 ) Ensure unsuccessful unauthorized file access attempts arecollected  $SEC\n"
else printf "\n$CIS (4.1.10|4.2.1.1|4.2.1.2|4.2.1.4 ) Ensure unsuccessful unauthorized file access attempts arecollected  $NO_SEC
Description:Monitor changes to file permissions, attributes, ownership and group. The parameters in
this section track changes for system calls that affect file permissions and attributes. The
chmod , fchmod and fchmodat system calls affect the permissions associated with a file. The
chown , fchown , fchownat and lchown system calls affect owner and group attributes on a
file. The setxattr , lsetxattr , fsetxattr (set extended file attributes) and removexattr ,
lremovexattr , fremovexattr (remove extended file attributes) control extended file
attributes. In all cases, an audit record will only be written for non-system user ids (auid >=
1000) and will ignore Daemon events (auid = 4294967295). All audit records will be
tagged with the identifier 'perm_mod'.

Monitor for unsuccessful attempts to access files. The parameters below are associated
with system calls that control creation ( creat ), opening ( open , openat ) and truncation (
truncate , ftruncate ) of files. An audit log record will only be written if the user is a non-
privileged user (auid > = 1000), is not a Daemon event (auid=4294967295) and if the
system call returned EACCES (permission denied to the file) or EPERM (some other
permanent error associated with the specific system call). All audit records will be tagged
with the identifier '.access'\n

rsyslog will create logfiles that do not already exist on the system. This setting controls
what permissions will be applied to these newly created files"
fi


#find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" + 2>&1
if  find /var/log -type f -ls 2>&1|grep -oi '-rw-r--r--'|wc -l| grep -q '0' ; then 
printf "\n$CIS 4.2.3 Ensure permissions on all logfiles are configured   $SEC\n"
else printf "\n$CIS 4.2.3 Ensure permissions on all logfiles are configured   $NO_SEC
Description: Log files stored in /var/log/ contain logged information from many services on the system,
or on log hosts others as well.\n"
fi

if  grep "^root:" /etc/passwd | cut -f4 -d: 2>&1| grep -q '0' ; then 
printf "\n$CIS 5.4.3 Ensure default group for the root account is GID 0   $SEC\n"
else printf "\n$CIS 5.4.3 Ensure default group for the root account is GID 0 $NO_SEC
Description:The usermod command can be used to specify which group the root user belongs to. This
affects permissions of files that are created by the root user.\n"
fi


if  stat /etc/passwd 2>&1|grep -io 'Access: (0644/-rw-r--r--)'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 6.1.2 Ensure permissions on /etc/passwd are configured   $SEC\n"
else printf "\n$CIS 6.1.2 Ensure permissions on /etc/passwd are configured $NO_SEC
Description:The /etc/passwd file contains user account information that is used by many system
utilities and therefore must be readable for these utilities to operate.\n"
fi

if stat /etc/gshadow- 2>&1|grep -io 'Access: (0640/-rw-r-----)'|wc -l| grep -vq '0' ; then 
printf "\n$CIS 6.1.3 Ensure permissions on /etc/gshadow- are configured   $SEC\n"
else printf "\n$CIS 6.1.3 Ensure permissions on /etc/gshadow- are configured $NO_SEC
Description:The /etc/gshadow- file is used to store backup information about groups that is critical to
the security of those accounts, such as the hashed password and other security
information.
\n"
fi












if grep "^\s*linux" /boot/grub/grub.cfg | grep -v "ipv6.disable=1"|wc -l| grep -q '0'; then
printf "\n$CIS 3.7 Disable IPv6 $SEC\n"
else printf "\n$CIS 3.7 Disable IPv6 $NO_SEC
Description:Although IPv6 has many advantages over IPv4, not all organizations have IPv6 or dual stack configurations implemented.Rationale:If IPv6 or dual stack is not to be used, it is recommended that IPv6 be disabled to reduce the attack surface of the system.\n"
fi

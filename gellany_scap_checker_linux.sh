#!/bin/bash

CIS="cis-ubuntu-linux-18.04"
NO_SEC="\033[1;31m[not secured]\033[0m"
SEC="\033[1;37m[secured]\033[0m"


if modprobe -n -v cramfs | grep -v mtd| grep -oi 'install /bin/true'|wc -l| grep -vq '0' || lsmod|grep cramfs|wc -l| grep -q '0'; then 
printf "\n$CIS 1.1.1.1 Ensure mounting of cramfs filesystems is disabled $SEC\n"
else printf "\n$CIS 1.1.1.1 Ensure mounting of cramfs filesystems is disabled $NO_SEC
Profile Applicability:Level 1 -Server:Level 1 -Workstation
Description:The cramfsfilesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfsimage can be used without having to first decompress the image.\n"
fi


if grep "^\s*linux" /boot/grub/grub.cfg | grep -v "ipv6.disable=1"|wc -l| grep -q '0'; then
printf "\n$CIS 3.7 Disable IPv6 $SEC\n"
else printf "\n$CIS 3.7 Disable IPv6 $NO_SEC
Profile Applicability:Level 2 -Server:Level 2 -Workstation
Description:Although IPv6 has many advantages over IPv4, not all organizations have IPv6 or dual stack configurations implemented.Rationale:If IPv6 or dual stack is not to be used, it is recommended that IPv6 be disabled to reduce the attack surface of the system.\n"
fi

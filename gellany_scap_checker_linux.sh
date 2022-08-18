 #!/bin/bash
 
if grep "^\s*linux" /boot/grub/grub.cfg | grep -v "ipv6.disable=1"|wc -l| grep -q '0'; then
  echo "matched"
fi

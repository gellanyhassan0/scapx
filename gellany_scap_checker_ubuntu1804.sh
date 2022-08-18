wget https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/scc-5.5_ubuntu18_ubuntu20_amd64_bundle.zip
wget https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/SCC_5.5_UNIX_Remote_Scanning_Plugin.zip
unzip scc-5.5_ubuntu18_ubuntu20_amd64_bundle.zip
unzip SCC_5.5_UNIX_Remote_Scanning_Plugin.zip
cd scc-5.5_ubuntu18_amd64
dpkg -i scc-5.5.ubuntu.18_amd64.deb
cd /opt/scc
./scc

#import SCC_5.5_UNIX_Remote_Scanning_Plugin.scc to connect ssh

sudo cp -vr ~/windows_share/flank.vpn ~/
sudo chown -R $USER:$USER ~/flank.vpn
sudo find ~/flank.vpn -type d -exec chmod 755 {} \; -exec chown $USER:$USER {} \;
sudo find ~/flank.vpn -type f -exec chmod 644 {} \; -exec chown $USER:$USER {} \;
mkdir -p ~/flank.vpn/build
cd ~/flank.vpn/build
cmake .. -DCMAKE_BUILD_TYPE=Release
make clean && make

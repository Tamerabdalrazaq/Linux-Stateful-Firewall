sudo mknod /dev/fw_log c 243 0
sudo python3 ./user/main.py load_rules rules
sudo python3 ./user/main.py show_rules
sudo python3 ./user/main.py show_log

sudo mknod /dev/fw_log c 243 0
python3 ./user/main.py load_rules rules
python3 ./user/main.py show_rules
python3 ./user/main.py show_log
cat python3 ./user/main.py show_log

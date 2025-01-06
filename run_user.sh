sudo mknod /dev/fw_log c 243 0
echo "Loading Rules.."
sudo python3 ./user/main.py load_rules rules
sudo python3 ./user/main.py show_rules
echo "Current Logs:"
sudo python3 ./user/main.py show_log
echo "Connections Table .."
sudo python3 ./user/main.py show_conns

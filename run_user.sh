sudo mknod /dev/fw_log c 243 0
echo ""
echo "Loading Rules.."
sudo python3 ./user/main.py load_rules rules
echo ""
echo ""
sudo python3 ./user/main.py show_rules
echo ""
echo ""
echo "Current Logs:"
sudo python3 ./user/main.py show_log
echo ""
echo ""
echo "Connections Table .."
sudo python3 ./user/main.py show_conns
# sudo python3 ./http/http_mitm.py
sudo python3 ./ftp/ftp_mitm.py
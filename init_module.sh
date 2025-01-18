sudo rmmod firewall;
cd module;
make;
sudo insmod firewall.ko;
cd ..;
sudo python3 ./http/http_mitm.py > http_output.log 2>&1 &
echo "HTTP proxy activated"
sudo python3 ./ftp/ftp_mitm.py > ftp_output.log 2>&1 &
echo "FTP proxy activated"
echo ""
bash run_user.sh;
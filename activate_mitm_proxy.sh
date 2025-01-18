sudo python3 ./http/http_mitm.py >/dev/tty 2>/dev/tty &
echo "HTTP proxy activated"
sudo python3 ./ftp/ftp_mitm.py >/dev/tty 2>/dev/tty &
echo "FTP proxy activated"
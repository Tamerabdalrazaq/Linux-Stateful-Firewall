sudo python3 .proxies//http/http_mitm.py >/dev/tty 2>/dev/tty &
echo "HTTP proxy activated"
sudo python3 .proxies/ftp/ftp_mitm.py >/dev/tty 2>/dev/tty &
echo "FTP proxy activated"
sudo python3 .proxies/smtp/smtp_mitm.py >/dev/tty 2>/dev/tty &
echo "SMTP proxy activated"
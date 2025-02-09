#!/bin/bash

if [[ "$1" == "http" || "$1" == "all" ]]; then
    sudo python3 .proxies/http/http_mitm.py
    echo "HTTP proxy activated"
elif [[ "$1" == "ftp" || "$1" == "all" ]]; then
    sudo python3 .proxies/ftp/ftp_mitm.py
    echo "FTP proxy activated"
elif [[ "$1" == "smtp" || "$1" == "all" ]]; then
    sudo python3 .proxies/smtp/smtp_mitm.py
    echo "SMTP proxy activated"
else 
    echo "Invalid argument. Use: \n bash activate_proxies.sh ['http', 'ftp', 'smtp', 'all']"
fi


sudo python3 .proxies//http/http_mitm.py >/dev/tty 2>/dev/tty &
echo "HTTP proxy activated"
sudo python3 .proxies/ftp/ftp_mitm.py >/dev/tty 2>/dev/tty &
echo "FTP proxy activated"
sudo python3 .proxies/smtp/smtp_mitm.py >/dev/tty 2>/dev/tty &
echo "SMTP proxy activated"
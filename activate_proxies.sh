#!/bin/bash

cd proxies;
if [[ "$1" == "http" ]]; then
    cd http;
    sudo python3 http_mitm.py && echo "HTTP proxy activated";
    cd ..;
elif [[ "$1" == "ftp" ]]; then
    cd ftp;
    sudo python3 ftp_mitm.py && echo "FTP proxy activated";
    cd ..;
elif [[ "$1" == "smtp" ]]; then
    cd smtp;
    sudo python3 smtp_mitm.py && echo "SMTP proxy activated";
    cd ..;

elif [[ "$1" == "all" ]]; then
    sudo echo ""
    cd http;
    echo "Activating HTTP proxy";
    sudo python3 http_mitm.py >/dev/tty 2>/dev/tty &
    cd ..;
    cd ftp;
    echo "Activating ftp proxy";
    sudo python3 ftp_mitm.py >/dev/tty 2>/dev/tty &
    cd ..;
    cd smtp;
    echo "Activating smtp proxy";
    sudo python3 smtp_mitm.py >/dev/tty 2>/dev/tty &
    cd ..;
    
else 
    echo "Invalid argument. Use: \n bash activate_proxies.sh ['http', 'ftp', 'smtp', 'all']";
fi
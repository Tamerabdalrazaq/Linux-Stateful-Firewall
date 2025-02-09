#!/bin/bash

cd proxies;
if [[ "$1" == "http" ]]; then
    cd http;
    echo "Activating HTTP proxy";
    sudo python3 http_mitm.py;
    cd ..;
elif [[ "$1" == "ftp" ]]; then
    cd ftp;
    echo "Activating FTP proxy";
    sudo python3 ftp_mitm.py; 
    cd ..;
elif [[ "$1" == "smtp" ]]; then
    cd smtp;
    echo "Activating SMTP proxy"
    sudo python3 smtp_mitm.py;
    cd ..;
else 
    echo "Invalid argument. Use: \n bash activate_proxies.sh ['http', 'ftp', 'smtp']";
fi
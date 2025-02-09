#!/bin/bash

cd proxies;
if [[ "$1" == "http" || "$1" == "all" ]]; then
    cd http;
    sudo python3 http_mitm.py && echo "HTTP proxy activated";
    cd ..;
elif [[ "$1" == "ftp" || "$1" == "all" ]]; then
    cd ftp;
    sudo python3 ftp_mitm.py && echo "FTP proxy activated";
    cd ..;
elif [[ "$1" == "smtp" || "$1" == "all" ]]; then
    cd smtp;
    sudo python3 smtp_mitm.py && echo "SMTP proxy activated";
    cd ..;
else 
    echo "Invalid argument. Use: \n bash activate_proxies.sh ['http', 'ftp', 'smtp', 'all']";
fi
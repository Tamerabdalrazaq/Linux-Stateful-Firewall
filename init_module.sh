sudo rmmod firewall;
cd module;
make;
sudo insmod firewall.ko;
cd ..;
echo ""
bash run_user.sh;
sudo rmmod firewall;
git pull;
cd module;
make;
sudo insmod firewall.ko;
cd ..;
bash run_user.sh;
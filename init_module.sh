sudo rmmod firewall;
git pull;
cd module;
make;
sudo insmod firewall.ko;
bash run_user.sh;
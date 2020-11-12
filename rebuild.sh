sudo rmmod custom_tcp_filter
make clean
make
sudo insmod custom_tcp_filter.ko

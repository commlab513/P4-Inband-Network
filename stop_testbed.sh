#!/bin/bash
sudo killall run_sft.sh
sudo killall run_mft.sh
echo "Kill local services"
sudo killall python;
sudo pkill -9 ./P4-Inband-Controller.py
echo "Deleting OVS configure..."
sudo ovs-vsctl --if-exists del-br br-control >/dev/null 2>&1
sudo ip link del vif-raw-port >/dev/null 2>&1
echo "Destory controller..."
ps -aux| grep Single-Failure-Test|awk '{print $2}'|xargs sudo kill -9 >/dev/null 2>&1
ps -aux| grep Multiple-Failure-Test|awk '{print $2}'|xargs sudo kill -9 >/dev/null 2>&1
sudo killall ryu-manager >/dev/null 2>&1
sudo kill -9 $(lsof -t -i :50000) >/dev/null 2>&1
sudo kill -9 $(lsof -t -i :50050) >/dev/null 2>&1

for j in $(seq 1 25); do
    echo "Kill P4 Switch $(printf "%d" $((140+j)))"
    IP="192.168.1.$((140+j))"
    ssh mountain@$IP "sudo kill -9 $(ps -aux | grep iperf | awk '{print $2}')" >/dev/null 2>&1
    ssh mountain@$IP "sudo kill -9 $(ps -aux | grep simple_switch_grpc | awk '{print $2}')" >/dev/null 2>&1
    ssh mountain@$IP "sudo kill -9 $(ps -aux | grep python3 | awk '{print $2}')" >/dev/null 2>&1
    ssh mountain@$IP "sudo kill -9 $(ps -aux | grep iperf | awk '{print $2}')" >/dev/null 2>&1
    ssh mountain@$IP "sudo kill -9 $(lsof -t -i :50000);" >/dev/null 2>&1
    ssh mountain@$IP "sudo kill -9 $(lsof -t -i :50050);" >/dev/null 2>&1
    ssh mountain@$IP "sudo ip link del vif-p4-switch > /dev/null 2>&1 " >/dev/null 2>&1
    ssh mountain@$IP "sudo ip link del vif-switch-1 > /dev/null 2>&1" >/dev/null 2>&1
done
sleep 5
sudo killall ssh >/dev/null 2>&1
sudo killall sshpass >/dev/null 2>&1
#!/bin/bash 
declare -a INTERFACES
declare -a TOPOLOGY
declare -a TEST_TYPE
declare -a SEED
declare -a ALL_INTERFACES
declare -a NETWORK_MONITORING_TIME_INTERVAL
INTERFACES="enp1s0 enp2s0 enp3s0 "
SW_DISCOVERY_TIME_INTERVAL=5
# NETWORK_MONITORING_TIME_INTERVAL="0.01 0.03 0.05 0.07"
# TOPOLOGY="1 "
# TEST_TYPE="3"
# COUNT="10"
# SEED="1132 7144 1385 64884 1354"
NETWORK_MONITORING_TIME_INTERVAL="0.02"
TOPOLOGY="4 "
TEST_TYPE="1 2"
COUNT=50

ALL_INTERFACES="${INTERFACES} vif-raw-port vif-ovs-port"
echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
echo "Initial configuring system. "
for topology in $TOPOLOGY; do
    for nmti in $NETWORK_MONITORING_TIME_INTERVAL; do
        for tt in $TEST_TYPE; do
            for ((c=0;c<=COUNT;c++)); do
                sudo ovs-vsctl add-br br-control 
                if ! ip link show vif-ovs-port &> /dev/null; then
                    sudo ip link add vif-ovs-port type veth peer name vif-raw-port 
                    sudo ip link set vif-ovs-port up
                    sudo ip link set vif-raw-port up
                fi
                sudo ovs-vsctl add-port br-control vif-ovs-port
                sudo ip address add 172.16.50.1/24 dev vif-raw-port
                sudo ip address add 172.16.50.2/24 dev vif-raw-port
                
                for intf in $ALL_INTERFACES; do
                    TOE_OPTIONS="rx tx sg tso ufo gso gro lro rxvlan txvlan ntuple rxhash"
                    sudo ifconfig $intf up
                    sudo ifconfig $intf promisc
                    for TOE_OPTION in $TOE_OPTIONS; do
                        sudo  /sbin/ethtool --offload $intf "$TOE_OPTION" off >/dev/null 2>&1 &
                    done
                    sudo /sbin/ethtool -s $intf speed 100 duplex full >/dev/null 2>&1 &
                    sudo sysctl net.ipv6.conf.$intf.disable_ipv6=1 >/dev/null 2>&1 &
                done
                sudo ovs-vsctl set-controller br-control tcp:127.0.0.1:6633
                sudo ovs-vsctl set bridge br-control other-config:datapath-id=0x00000000001
                for intf in $INTERFACES; do
                    sudo ovs-vsctl add-port br-control $intf
                done
                DATE=$(date +"%d-%m-%Y_%H:%M:%S")
                mkdir switch_log/$DATE
                echo "Reset testbed, waiting 10s..."
                for j in $(seq 1 25); do
                    IP="192.168.1.$((140+j))"
                    P4S=$(printf "p4s%d.log" $((140+j)))
                    ssh mountain@$IP "cd Switch; sudo chrt -f 99 python3 ./receiver.py; " > switch_log/$DATE/$P4S 2>&1 & 
                done
                P4S=$(printf "p4s0.log" $j)
                sudo chrt -f 99 ryu-manager ./failure_controller.py > switch_log/$DATE/$P4S 2>&1 &
                echo "Configuration [OpenVSwitch]"
                sudo ovs-ofctl del-flows br-control;
                sudo ovs-ofctl add-flow br-control priority=1,in_port=2,eth_type=0x0800,nw_proto=254,action=set_field:"04:00:00:00:00:02"-\>dl_dst,Output:vif-ovs-port
                sudo ovs-ofctl add-flow br-control priority=1,in_port=3,eth_type=0x0800,nw_proto=254,action=set_field:"04:00:00:00:00:03"-\>dl_dst,Output:vif-ovs-port
                sudo ovs-ofctl add-flow br-control priority=1,in_port=4,eth_type=0x0800,nw_proto=254,action=set_field:"04:00:00:00:00:04"-\>dl_dst,Output:vif-ovs-port
                sudo ovs-ofctl add-flow br-control priority=1,in_port=vif-ovs-port,action=Output:NORMAL
                sudo ovs-ofctl add-flow br-control priority=0,in_port=2,action=Output:vif-ovs-port
                sudo ovs-ofctl add-flow br-control priority=0,in_port=3,action=Output:vif-ovs-port
                sudo ovs-ofctl add-flow br-control priority=0,in_port=4,action=Output:vif-ovs-port
                sleep 10
                script -c "sudo chrt -f 99 python3 ./Multiple-Failure-Test.py ./topology-profiles/$topology.json $SW_DISCOVERY_TIME_INTERVAL $nmti $c 0 $tt" ./controller_log/system_log_$DATE.log
                sudo killall ryu-manager >/dev/null 2>&1
                sudo killall python3 >/dev/null 2>&1
                sudo kill -9 $(lsof -t -i :50050) >/dev/null 2>&1
                sudo kill -9 $(lsof -t -i :50000) >/dev/null 2>&1
                sudo kill -9 $(ps -aux | grep Multiple-Failure-Test.py | awk '{print $2}') >/dev/null 2>&1
                sudo kill -9 $(ps -aux | grep ryu-manager | awk '{print $2}') >/dev/null 2>&1
                sudo ovs-ofctl del-flows br-control;
                for j in $(seq 1 25); do
                    IP="192.168.1.$((140+j))"
                    ssh mountain@$IP "sudo kill -9 \$(ps -aux | grep iperf | awk '{print \$2}')"  >/dev/null 2>&1
                    ssh mountain@$IP "sudo kill -9 \$(ps -aux | grep simple_switch_grpc | awk '{print \$2}')"  >/dev/null 2>&1
                    ssh mountain@$IP "sudo kill -9 \$(ps -aux | grep python3 | awk '{print \$2}')"  >/dev/null 2>&1
                    ssh mountain@$IP "sudo kill -9 \$(ps -aux | grep iperf | awk '{print \$2}')"  >/dev/null 2>&1
                    ssh mountain@$IP "sudo kill -9 $(lsof -t -i :50000);"  >/dev/null 2>&1
                    ssh mountain@$IP "sudo kill -9 $(lsof -t -i :50050);"  >/dev/null 2>&1
                    ssh mountain@$IP "sudo ip link del vif-p4-switch >/dev/null 2>&1 "  >/dev/null 2>&1
                    ssh mountain@$IP "sudo ip link del vif-switch-1 >/dev/null 2>&1 "  >/dev/null 2>&1
                done
                sudo ovs-vsctl --if-exists del-br br-control
                sudo ip link del vif-raw-port >/dev/null 2>&1
                echo "Rest testbed, waiting 30s..."
                sleep 30
            done
            echo "Rest testbed, waiting 30s..."
            sleep 30
        done        
    done        
done

echo "Process killing [SSH]"
sudo killall ssh >/dev/null 2>&1
sudo killall sshpass >/dev/null 2>&1
echo "Finish, exiting"
exit 0


#!/usr/bin/python3
import socket
import threading
import select
import time
import json
import os
import subprocess
import struct
import logging
import signal
import psutil
class SwitchController ():
    def __init__(self):
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.bind(("0.0.0.0",50000))
        self.tcp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
        self.tcp_sock.listen(1)
        self.switch_ip = None
        self.host_ip = None
        self.switch_id = None
        self.switch_pid = None
        self.physical_interface = None
        self.interface_list = ["vif-p4-switch", "vif-grpc-server", "vif-switch-1", "vif-host-1"]
        self.traffics = []
        subprocess.call("echo \"performance\" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor", shell=True)
        return
    
    def receiver(self):
        conn, addr = self.tcp_sock.accept()
        offload = ["rx","tx", "sg", "tso", "ufo", "gso", "gro", "lro", "rxvlan", "txvlan", "rxhash"]
        while (True):
            msg_size = conn.recv(struct.calcsize("i"))
            if (len(msg_size) <= 0):
                if (self.switch_pid != None):
                    self.switch_pid.kill()
                self.tcp_sock.close()
                return
            size = struct.unpack("i", msg_size)[0]
            msg = conn.recv(size)
            msg = msg.decode()
            command, action = msg.split("_")
            if (command == "c"): # configuration
                switch_id, switch_ip, host_ip, physical_interface = action.split("/")
                self.switch_id = int(switch_id)
                self.switch_ip = switch_ip
                self.host_ip = host_ip
                self.physical_interface = physical_interface.split("-")
                subprocess.call("ip link add vif-p4-switch type veth peer name vif-grpc-server", shell=True)
                subprocess.call("ip link add vif-switch-1 type veth peer name vif-host-1", shell=True)
                subprocess.call("ifconfig vif-grpc-server hw ether 08:00:00:00:00:%02x"%self.switch_id, shell=True)
                interface_list = [] 
                interface_list = list(self.interface_list)+list(self.physical_interface)
                for i in interface_list:
                    for j in offload:
                        subprocess.call("/sbin/ethtool --offload %s %s off"%(i, j), shell=True)
                    subprocess.call("sysctl net.ipv6.conf.%s.disable_ipv6=1"%i, shell=True)
                    subprocess.call("ethtool -s %s speed 100 duplex full"%i, shell=True)
                    subprocess.call("ifconfig %s promisc"%i, shell=True)
                    subprocess.call("ifconfig %s up"%i, shell=True)
                subprocess.call("ifconfig vif-host-1 %s/24 up"%self.host_ip, shell=True)
                subprocess.call("ifconfig vif-grpc-server %s/24 up"%self.switch_ip, shell=True)
            elif (command == "s"): # switch
                if (action == "start"):
                    iface_list = ["-i", "254@vif-p4-switch", "-i", "250@vif-switch-1"]
                    for i in range(len(self.physical_interface)):
                        iface_list += ["-i", "%d@%s"%(i+1,self.physical_interface[i])]
                    switch_cmd = ["chrt", "-f", "99", "simple_switch_grpc"]+iface_list
                    switch_cmd += ["--device-id", "%s"%self.switch_id, "switch.json", "--", "--grpc-server-addr", "0.0.0.0:50051", "--cpu-port", "255", "--priority-queues", "2"]
                    # "--thrift-port", "9090", 
                    self.switch_pid = subprocess.Popen(switch_cmd, stdin=subprocess.PIPE, close_fds=True, preexec_fn = os.setsid)
                elif (action == "stop"):
                    parent = psutil.Process(self.switch_pid.pid)
                    for child in parent.children(recursive=True): 
                        child.kill()
                    parent.kill()
                    subprocess.call("sudo kill -9 \$\(ps -aux | grep simple_switch_grpc | awk \'{print \$2}\'\)", shell=True)
                    self.switch_pid = None
            elif (command == "l"):
                interface_list = action.split("-")
                # print (interface_list)
                for info in interface_list:
                    iface, state = info.split(":")
                    if (state == "down"):
                        subprocess.call("ifconfig %s down"%iface, shell=True)
                    elif (state == "up"):
                        for j in offload:
                            subprocess.call("/sbin/ethtool --offload %s %s off"%(iface, j), shell=True)
                        subprocess.call("sysctl net.ipv6.conf.%s.disable_ipv6=1"%iface, shell=True)
                        subprocess.call("ethtool -s %s speed 100 duplex full"%iface, shell=True)
                        subprocess.call("ifconfig %s promisc"%iface, shell=True)
                        subprocess.call("ifconfig %s up"%iface, shell=True)
            elif (command == "b"): # traffic
                target_ip, bw, timeout = action.split("/")
                cmd = ["iperf", "-c", target_ip, "-u", "-b", "%sm"%bw, "-l",  "1472", "-t", timeout]
                self.traffics.append(subprocess.Popen(cmd, stdin=subprocess.PIPE, close_fds=True, preexec_fn = os.setsid))
            elif (command == "k"): # traffic
                for t in self.traffics:
                    parent = psutil.Process(t.pid)
                    for child in parent.children(recursive=True): 
                        child.kill()
                    parent.kill()
                self.traffics = []
            
if __name__ == "__main__":
    switch_controller = SwitchController()
    switch_controller.receiver()
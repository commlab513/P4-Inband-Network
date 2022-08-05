#!/usr/bin/env python3
import os,sys,json
import socket
from time import sleep, time
from struct import pack, unpack
from threading import Timer

os.chdir(os.path.dirname(os.path.realpath(__file__)))

def _byteify(data):
    if isinstance(data, str):
        value = data
        try:
            value = int(value)
        except ValueError:
            pass
        finally:
            return value
    if isinstance(data, list):
        return [ _byteify(item) for item in data ]
    if isinstance(data, dict):
        return { _byteify(key): _byteify(value) for key, value in data.items() }
    return data

class Testbed:
    def __init__(self, filename):
        #Read json files
        self.tcp_socket = {}
        f = open("./topology-profiles/PM_Information_9_nodes.json", "r")
        self.p4_device_information = _byteify(json.load(f, object_hook=_byteify))
        f.close()
        f = open(filename, "r")
        self.topology = _byteify(json.load(f, object_hook=_byteify))
        f.close()
        # Testbed Control Information
        for sw_id in self.p4_device_information:
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            tcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
            tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            tcp_socket.connect((self.p4_device_information[sw_id]['control_ip'], 50000))
            self.tcp_socket.setdefault(sw_id, tcp_socket)
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        tcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
        tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        tcp_socket.connect(("127.0.0.1", 50000))
        self.tcp_socket.setdefault(-1, tcp_socket)
        self.read_file(filename)
        return

    def send_cmd(self, sid, cmd):
        cmd = cmd.encode()
        length = pack("i",len(cmd))
        self.tcp_socket[sid].send(length+cmd)
        return 
    
    def configuration(self, p4sid):
        switch_ip = self.p4_device_information[p4sid]["switch_ip"]
        host_ip = self.p4_device_information[p4sid]["host_ip"]
        interfaces = "-".join(self.p4_device_information[p4sid]["interfaces"])
        self.send_cmd(p4sid, "c_%s/%s/%s/%s"%(p4sid,switch_ip,host_ip,interfaces))
    
    def network_setup (self, p4sid, topology, action): 
        if topology == 1:
            topology_name = "control_topology"
        elif topology == 2:
            topology_name = "test_topology"
        elif topology == 3:
            topology_name = "full_topology"
        if action == 1:
            action_name = "up"
        elif action == 2:
            action_name = "down"
        interfaces_list = []
        # print (p4sid, self.p4_device_information[p4sid]["interfaces"])
        if (p4sid in self.topology[topology_name]):
            for i in self.topology[topology_name][p4sid]:
                port = self.topology[topology_name][p4sid][i]
                port_name = self.p4_device_information[p4sid]["interfaces"][port-1]
                interfaces_list.append("%s:%s"%(port_name, action_name))
            interfaces = "-".join(interfaces_list)
            self.send_cmd(p4sid, "l_%s"%(interfaces))
    
    def switch_control (self, action, p4sid):
        if (action == 1):
            self.send_cmd(p4sid, "s_start")
        elif (action == 2):
            self.send_cmd(p4sid, "s_stop")
    
    def background_traffic_iperf(self, bw, timeout):
        for i in self.topology["ryu_topology"]:
            for j in self.topology["ryu_topology"][i]:
                if i!=0 and j!=0:
                    target_ip = self.p4_device_information[j]["host_ip"]
                    self.send_cmd(i, "b_%s/%d/%d"%(target_ip,bw,timeout))
        return
    def kill_iperf (self, sw_id):
        self.send_cmd(sw_id, "k_NA")
        return 
    # OpenFlow Controller
    def read_file (self, file_path):
        self.send_cmd(-1, "topology_%s"%file_path)
        return 
    
    def link_up_down (self, action, nodeA, nodeB, timeout):
        if (action == 1):
            sleep(timeout - time())
            self.send_cmd(-1, "link_down-%.6f-%d/%d"%(0, nodeA, nodeB))
        elif (action == 2):
            self.send_cmd(-1, "link_up-%.6f-%d/%d"%(0, nodeA, nodeB))
        return 
    
    def node_up_down (self, action, node, timeout):
        if (action == 1):
            sleep(timeout - time())
            self.switch_control(2, node)
        elif (action == 2):
            self.configuration(node)
            sleep(5)
            self.switch_control(1, node)
        return 
    
    def initialization(self, sid):
        self.configuration(sid)
        sleep(5)
        self.switch_control(1,sid)
    
    def kill_service(self):
        print ("Killing control socket services")
        for t in self.tcp_socket:
            self.tcp_socket[t].close()
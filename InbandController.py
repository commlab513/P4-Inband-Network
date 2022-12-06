#!/usr/bin/env python3
import os,sys,random,json,copy
import socket
import networkx as nx
import p4_runtime.bmv2
import p4_runtime.helper
import traceback
from time import sleep, time
from struct import pack, unpack
from threading import Thread,Timer,Lock
from scapy.all import Ether, IP

PREAMBLE = 0x1122334455667788
P4_FILE_PATH = "./p4_script/build/"
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

class P4_GRPC_Connection:
    def __init__(self, switch_ip, switch_id, grpc_connection, p4info_helper, control_path, control_port):
        self.switch_ip = switch_ip
        self.switch_id = switch_id
        self.grpc_connection = grpc_connection
        self.p4info_helper = p4info_helper
        self.control_path = control_path
        self.control_port = control_port
        self.node_detection = 0
        self.node_detection_path = []
        self.node_detection_packet = None
        return 

class Controller():
    def __init__ (self, switch_discovery_time_interval, network_monitoring_time_interval):
        self.Process_Stop_Flag = False
        self.switch_discovery_time_interval = float(switch_discovery_time_interval)
        self.network_monitoring_time_interval = float(network_monitoring_time_interval)
        self.thread_lock = Lock()
        
        f = open("./p4_script/p4_files/swinfo.json", "r")
        self.switch_registration_information = _byteify(json.load(f, object_hook=_byteify))
        f.close()

        # Control channel setting
        self.mac_address_list = {
            "04:00:00:00:00:02":2,
            "04:00:00:00:00:03":3,
            "04:00:00:00:00:04":4,
        }
        self.control_socket = {
            "ip": ["172.16.50.1","172.16.50.2"],
            "proto": [254,254],
            "socket":[]
        } 
        self.P4IBN_raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.P4IBN_raw_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.P4IBN_raw_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
        self.P4IBN_raw_socket.bind(("vif-raw-port", 0))
        for i in range(0,len(self.control_socket['ip'])):
            addr = self.control_socket['ip'][i]
            P4IBN_sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.control_socket['proto'][i])
            P4IBN_sender.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            P4IBN_sender.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
            P4IBN_sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 64)
            P4IBN_sender.bind((addr, 0))
            self.control_socket["socket"].append(P4IBN_sender)
        self.control_flow_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.control_flow_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.control_flow_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
        self.control_flow_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.control_flow_socket.connect(("127.0.0.1", 50050))
        self.switch_information = {}
        self.configuration_update_waiting_list = {}
        self.switch_information.setdefault(0, P4_GRPC_Connection("224.0.0.200", 0, None, None, [0], None, None))
        self.switch_discovery_timer = None

        self.port_attack_list = {0:{}}
        self.topology = {0:{}}
        self.direct_link_set = []
        self.composited_link_set = []
        self.composited_LSP = []
        self.direct_LSP = []
        self.control_path_tree = {}
        self.control_path_tree.setdefault(0, {"root": -1, "nodes": []})

        self.failureLSP = {}
        self.failure_cases = []
        self.recovery_path_tree = {}
        self.recovery_path_entries = {}
        self.configuration_network_flag = False
        self.recovery_node_list = []
        # Testing Informaiton
        self.orginal_switch_information = {}
        self.orginal_control_path_tree = None
        self.control_failure_cases = []
        p = Thread(target=self.message_receiver)
        p.setDaemon(True)
        p.start()
        
        return
    # Funciton for contorlling OVS, for seperating control traffics to difference subtree
    def ovs_command(self, action, switch_ip, control_ip, output):
        if (action == 1):
            command = "add"
        elif (action == 2):
            command = "del"
        cmd = ("cf_%s-%s-%s-%s"%(command,switch_ip,control_ip,output)).encode()
        length = pack("i",len(cmd))
        self.control_flow_socket.send(length+cmd)
    
    # Funcitons for P4 Flow entries configuration, controlling and monitoring P4 inband network 
    def _write_broadcast_group_rules(self, p4info_helper):
        table_entries = []
        replicas = []
        multicast_group_id  = 200
        for port in [1,2,3,4,5,6]:
            replicas.append({"instance":1, "egress_port":port})
        table_entries.append((0, 1, p4info_helper.buildMulticastGroupEntry(multicast_group_id=multicast_group_id,replicas=replicas)))
        return table_entries

    def _write_arp_forwarding_rules (self, action, p4info_helper, ip_address, selected_action, priority=None, output=None):
        table_entries = []
        if (selected_action == 1):
            action_name = "MyIngress.set_output"
            action_params = { "priority":priority, "port": output }
        elif (selected_action == 2):
            action_name = "MyIngress.set_controller_port"
            action_params = {}
        table_entries.append((action, 0, p4info_helper.buildTableEntry(
            table_name="MyIngress.arp_forwarding",
            match_fields={  "hdr.arp_rarp_ipv4.dstProtoAddr": ip_address},
            action_name=action_name,
            action_params=action_params)))
        return table_entries

    def _write_ipv4_forwarding_rules (self, action, p4info_helper, ip_address, type_id, selected_action, priority=None, output=None):
        table_entries = []
        if (selected_action == 1):
            action_name = "MyIngress.set_output"
            action_params = { "priority":priority, "port": output }
        elif (selected_action == 2):
            action_name = "MyIngress.set_controller_port"
            action_params = {}
        table_entries.append((action, 0, p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_forwarding",
            match_fields={  "hdr.ipv4.dstAddr": ip_address, "metadata.forwarding_message_type": type_id},
            action_name=action_name,
            action_params=action_params)))
        return table_entries
    
    def _write_cu_switch_port_rules (self, action, p4info_helper, output):
        table_entry = [(action, 0, p4info_helper.buildTableEntry(
            table_name="MyIngress.cu_switch_port",
            match_fields={  "standard_metadata.ingress_port":output },
            action_name="NoAction",
            action_params={ }))]
        return table_entry
    
    def _write_sr_switch_port_rules (self, action, p4info_helper, output):
        table_entry = [(action, 0, p4info_helper.buildTableEntry(
            table_name="MyIngress.sr_switch_port",
            match_fields={  "standard_metadata.ingress_port":output },
            action_name="drop",
            action_params={ }))]
        return table_entry
    
    # Functions for control messages management, processing
    ## SR MSG
    ## LSU MSG
    ## CS MSG
    def parsing_control_message (self, msg):
        parsed_msg = {}
        payload = msg[34:]
        while (len(payload) > 0):
            msg_type = unpack("!B", payload[0])
            payload = payload[1:]
            if msg_type == 0x2: # SR
                code = [0,0,0,0,0,0]
                transit_switch_id, transit_switch_port_id, response_switch_id, response_switch_port_id, code[0], code[1], code[2], code[3], code[4], code[5] = unpack("!HHHH", payload[:14])
                switch_authentication_code = (code[0] << 40) + (code[1] << 32) + (code[2] << 24) + (code[3] << 16) + (code[4] << 8) + code[5]
                mac_address = "%02x:%02x:%02x:%02x:%02x:%02x" % unpack("BBBBBB",msg[:6])
                ovs_port = self.mac_address_list[mac_address] if (mac_address in self.mac_address_list.keys()) else 0xff
                if (transit_switch_id == 0):
                    transit_switch_port_id = ovs_port
                temp_data = {
                    "ovs_port": ovs_port, 
                    "transit_switch_id": transit_switch_id, 
                    "transit_switch_port_id": transit_switch_port_id, 
                    "response_switch_id": response_switch_id, 
                    "response_switch_port_id": response_switch_port_id, 
                    "switch_authentication_code": switch_authentication_code, 
                }
                parsed_msg.setdefault("switch_registration", temp_data)
                break
            elif msg_type == 0x3: # NM
                transit_switch_id, transit_switch_port_id = unpack("!HH", payload[:4])
                response_switch_id = 0
                response_switch_port_id = 0xff
                mac_address = "%02x:%02x:%02x:%02x:%02x:%02x" % unpack("BBBBBB",msg[0:6])
                if (mac_address in self.mac_address_list.keys()):
                    response_switch_id = 0
                    response_switch_port_id = msg[5]
                temp_data = {
                    "transit_switch_id": transit_switch_id,
                    "response_switch_id": response_switch_id,
                    "transit_switch_port_id": transit_switch_port_id, 
                    "response_switch_port_id": response_switch_port_id
                }
                parsed_msg.setdefault("link_state_update", temp_data)
                break
            elif msg_type == 0x4: # LSU
                transit_switch_id, transit_switch_port_id, response_switch_id, response_switch_port_id = unpack("!HHHH", payload[:8])
                temp_data = {
                    "transit_switch_id": transit_switch_id,
                    "response_switch_id": response_switch_id,
                    "transit_switch_port_id": transit_switch_port_id, 
                    "response_switch_port_id": response_switch_port_id
                }
                parsed_msg.setdefault("link_state_update", temp_data)
                break
            elif msg_type == 0x6: # CS
                response_switch_id, response_switch_port_id = unpack("!HH", payload[:4])
                temp_data = {
                    "response_switch_id": response_switch_id,
                    "response_switch_port_id": response_switch_port_id
                }
                parsed_msg.setdefault("configuration_sucess", temp_data)
                break
            elif msg_type == 0x8: # SQR
                response_switch_id, response_switch_port_id = unpack("!HH", payload[:4])
                temp_data = {
                    "response_switch_id": response_switch_id,
                    "response_switch_port_id": response_switch_port_id,
                }
                parsed_msg.setdefault("switch_alive_response", temp_data)
                break
        return parsed_msg
    
    def message_receiver(self):
        try:
            while (not(self.Process_Stop_Flag)):
                msg = self.P4IBN_raw_socket.recv(128)
                if (msg[23]  == 254):
                    parsed_payload = self.parsing_control_message(msg)
                    if ("switch_registration" in parsed_payload):
                        if (self.configuration_network_flag == False and switch_id not in self.switch_information):
                            Thread(target=self.switch_registration, args=(parsed_payload,)).start()
                    elif ("link_state_update" in parsed_payload):
                        src_switch_id = parsed_payload["link_state_update"]["transit_switch_id"]
                        dst_switch_id = parsed_payload["link_state_update"]["response_switch_id"]
                        port = parsed_payload["link_state_update"]["response_switch_port_id"]
                        if (not(dst_switch_id == 0 and port == 0xff)):
                            Thread(target=self.network_monitoring_process, args=(src_switch_id,dst_switch_id,port, )).start()
                    elif ("configuration_sucess" in parsed_payload):
                        response_switch_id = parsed_payload["configuration_sucess"]["response_switch_id"]
                        if response_switch_id in self.configuration_update_waiting_list:
                            del self.configuration_update_waiting_list[response_switch_id]
                    elif ("switch_alive_response" in parsed_payload):
                        self.switch_information[parsed_payload["switch_alive_response"]["response_switch_id"]].node_detection = 1
        except(KeyboardInterrupt):
            return
        return

    def network_monitoring_process(self, src_switch_id, dst_switch_id, port):
        if (src_switch_id == dst_switch_id):
            return
        elif (dst_switch_id in self.topology and src_switch_id in self.topology[dst_switch_id] and self.topology[dst_switch_id][src_switch_id] != port):
            return
        if (src_switch_id in self.topology and dst_switch_id in self.topology):
            if (self.configuration_network_flag == False and src_switch_id not in self.topology[dst_switch_id]):
                with self.thread_lock:
                    if (src_switch_id not in self.topology[dst_switch_id]):
                        if (dst_switch_id != 0):
                            entry = self._write_cu_switch_port_rules(0, self.switch_information[dst_switch_id].p4info_helper,port)
                            self.switch_information[dst_switch_id].grpc_connection.WriteTableEntry(entry)
                        self.topology[dst_switch_id].setdefault(src_switch_id, port)
                        self.direct_link_set.append((dst_switch_id,src_switch_id))
                        self.direct_LSP.append(1)
                        if ((src_switch_id,dst_switch_id) not in self.composited_link_set):
                            self.composited_link_set.append((dst_switch_id,src_switch_id))
                            self.composited_LSP.append(1)
            else:
                if ((src_switch_id, dst_switch_id) in self.direct_link_set):
                    self.direct_LSP[self.direct_link_set.index((src_switch_id, dst_switch_id))] = 1
        return
    
    def switch_registration (self, parsed_payload):
        switch_id = parsed_payload["switch_registration"]["response_switch_id"]
        switch_ip = self.switch_registration_information[switch_id]["switch_ip"]
        output_port = parsed_payload["switch_registration"]["response_switch_port_id"]
        pre_switch_id = parsed_payload["switch_registration"]["transit_switch_id"]
        pre_forward_port = parsed_payload["switch_registration"]["transit_switch_port_id"]
        ovs_port = parsed_payload["switch_registration"]["ovs_port"]

        with self.thread_lock:
            if (switch_id not in self.switch_information):
                self.switch_information.setdefault(switch_id, None)
            else:
                if (pre_forward_port not in self.port_attack_list[pre_switch_id]):
                    self.port_attack_list[pre_switch_id].setdefault(pre_forward_port, 1)
                else:
                    self.port_attack_list[pre_switch_id][pre_forward_port] += 1
                if (self.port_attack_list[pre_switch_id][pre_forward_port] > 10):
                    p4info_helper = self.switch_information[pre_switch_id].p4info_helper
                    p4_table_entries = self._write_sr_switch_port_rules(0, p4info_helper, pre_forward_port)
                    self.switch_information[pre_switch_id].grpc_connection.WriteTableEntry(p4_table_entries)
                return 
            p4info_helper = p4_runtime.helper.P4InfoHelper(P4_FILE_PATH+"s%d/switch.p4info.txt"%switch_id)
            json_file = P4_FILE_PATH+"s%d/switch.json"%switch_id
            if (pre_switch_id > 0):
                path = self.switch_information[pre_switch_id].control_path
                p4info_helper = self.switch_information[pre_switch_id].p4info_helper
                p4_table_entries = self._write_cu_switch_port_rules(0, p4info_helper, pre_forward_port)
                self.switch_information[pre_switch_id].grpc_connection.WriteTableEntry(p4_table_entries)
            else:
                path = [0]
            delay = len(path)
            self.configuration_update_waiting_list.update(self.configuration_update_message_generator([(pre_switch_id,switch_id,pre_forward_port,output_port)]))
            result = self.send_configuration_update_message()
            if (result == True):
                self.ovs_command(1, switch_ip, control_ip, ovs_port)
                if (len(path) > 1):
                    for i in range(1,len(path)):
                        p4_table_entries = []
                        p4info_helper = self.switch_information[path[i]].p4info_helper
                        if (i==len(path)-1):
                            output = pre_forward_port
                        else:
                            output = self.topology[path[i]][path[i+1]]
                        p4_table_entries += self._write_arp_forwarding_rules(0, p4info_helper, switch_ip, 1, 1, output)
                        p4_table_entries += self._write_ipv4_forwarding_rules(0, p4info_helper, switch_ip, 0, 1, 1, output)
                        self.switch_information[path[i]].grpc_connection.WriteTableEntry(p4_table_entries)
                grpc_connection = p4_runtime.bmv2.Bmv2SwitchConnection(name='switch-%d'%switch_id, address='%s:50051'%(switch_ip), device_id=switch_id, low=1)
                item = grpc_connection.MasterArbitrationUpdate()
                count = 0
                while (True):
                    if (item == None and count < 5):
                        item = grpc_connection.MasterArbitrationUpdate()
                        sleep(0.01)
                        count += 1
                    else:
                        break
                if (item == None):
                    del self.switch_information[switch_id]
                    return
                grpc_connection.SetConfigureForwardingPipeline(action = 1, p4info=p4info_helper.p4info, bmv2_json_file_path=json_file)
                control_ip = self.control_socket['ip'][0]
                p4_table_entries = []
                p4_table_entries += self._write_broadcast_group_rules(p4info_helper)
                p4_table_entries += self._write_cu_switch_port_rules(0, p4info_helper, output_port)
                p4_table_entries += self._write_arp_forwarding_rules(0, p4info_helper, control_ip, 2)
                p4_table_entries += self._write_ipv4_forwarding_rules(0, p4info_helper, control_ip, 0, 2)
                grpc_connection.WriteTableEntry(p4_table_entries)

                self.configuration_update_waiting_list.update(self.configuration_update_message_generator([(pre_switch_id,switch_id,pre_forward_port,output_port)]))
                Timer(0.002*delay, self.send_configuration_update_message).start()
                grpc_connection.SetConfigureForwardingPipeline(action = 3, p4info=p4info_helper.p4info, bmv2_json_file_path=json_file)
                self.switch_information[switch_id] = P4_GRPC_Connection(switch_ip, switch_id, grpc_connection, p4info_helper, path+[switch_id], output_port)
                if (switch_id not in self.topology):
                    self.topology.setdefault(switch_id, {})
                    self.topology[switch_id].setdefault(pre_switch_id, output_port)
                    self.topology[pre_switch_id].setdefault(switch_id, pre_forward_port)
                    self.direct_link_set.append((pre_switch_id, switch_id))
                    self.direct_link_set.append((switch_id, pre_switch_id))
                    self.port_attack_list.setdefault(switch_id, {})
                    if (pre_forward_port in self.port_attack_list[pre_switch_id]):
                        del self.port_attack_list[pre_switch_id][pre_forward_port]
                    self.direct_LSP.append(1)
                    self.direct_LSP.append(1)
                    if ((switch_id, pre_switch_id) not in self.composited_link_set):
                        self.composited_link_set.append((pre_switch_id,switch_id))
                        self.composited_LSP.append(1)
                    self.control_path_tree.setdefault(switch_id, {"root": pre_switch_id, "nodes": []})
                    for p in path:
                        self.control_path_tree[p]["nodes"].append(switch_id)
                print ("Switch ID [%d]: connected! "%switch_id)      
                self.switch_discovery(sw_id = switch_id)
            else:
                del self.switch_information[switch_id]
        return
    
    # Functions for P4IBN, processing
    ## SD MSG
    ## NM MSG
    ## CU MSG
    def configuration_update_message_generator (self,configuration_update_messages):
        waiting_list = {}
        for i in configuration_update_messages:
            pre_switch_id, switch_id, pre_forward_port, output_port = i
            if (pre_switch_id == 0):
                IBCHeader = b''
                Payload = pack("!BHH",  switch_id, output_port)
                switch_ip = self.switch_information[switch_id].switch_ip
            else:
                IBCHeader = pack("!BH", 0xA, pre_forward_port)
                Payload = bytes(Ehter(src=self.switch_registration_information[switch_id]["mac_address"], dst=self.switch_registration_information[switch_id]["mac_address"])/IP(src=self.switch_infomration[pre_switch_id].switch_ip, dst=self.switch_infomration[switch_id].switch_ip, portocol=254))+pack("!BHH", 0x5, switch_id, output_port)
                switch_ip = self.switch_information[pre_switch_id].switch_ip
            waiting_list.setdefault(switch_id, {"message":IBCHeader+Payload, "switch_ip": switch_ip})
        return waiting_list

    def send_configuration_update_message (self):
        send_timer = 0
        while(len(self.configuration_update_waiting_list.keys()) > 0):
            if (send_timer % 50 == 0):
                for pair in list(self.configuration_update_waiting_list.keys()):
                    if (pair in self.configuration_update_waiting_list):
                        self.control_socket["socket"][0].sendto(self.configuration_update_waiting_list[pair]["message"], (self.configuration_update_waiting_list[pair]["switch_ip"],0))
            send_timer += 1
            sleep(0.001)
            if (send_timer == 200):
                return False
        return True
    
    def switch_discovery(self, sw_id=None):
        try:
            if (self.configuration_network_flag == False and self.Process_Stop_Flag == False):
                Payload = pack("!BHH", 0x1, 0x00, 0x00)
                if (sw_id == None):
                    for sw_id in dict(self.switch_information):
                        if (self.switch_information[sw_id] != None):
                            if (sw_id == 0):
                                IBCHeader = b''
                                switch_ip = "224.0.0.200"
                            else:
                                IBCHeader = pack("!B", 0x9)
                                switch_ip = self.switch_information[sw_id].switch_ip
                else: 
                    IBCHeader = pack("!B", 0x9)
                    swithc_ip = self.switch_information[sw_id].switch_ip
                self.control_socket["socket"][0].sendto(IBCHeader+Payload, (switch_ip,0))
        except(KeyboardInterrupt):
            return
        return

    def network_monitoring(self):
        for sw_id in list(self.switch_information.keys()):
            try:
                if (sw_id in self.switch_information and self.switch_information[sw_id] != None):
                    Payload = pack("!BHH", 0x3, 0x00, 0x00)
                    if (sw_id == 0):
                        IBCHeader = b''
                        switch_ip = "224.0.0.200"
                    else:
                        IBCHeader = pack("!B", 0x9)
                        switch_ip = self.switch_information[sw_id].switch_ip
                        if (len(self.switch_information[sw_id].node_detection_path) > 0):
                            node_detection_payload = pack("!BH", 0x7, sw_id)
                            self.control_socket["socket"][1].sendto(node_detection_payload, (switch_ip,0))
                    self.control_socket["socket"][0].sendto(IBCHeader+Payload, (switch_ip,0))
            except:
                pass
        return
    
    # Function for failure detection and management
    def failureLSP_calculator(self):
        for i in self.topology:
            if (i != 0):
                self.failure_cases.append(i)
                self.failureLSP.setdefault(len(self.failure_cases)-1,None)
            for j in self.topology[i]:
                if (j,i) not in self.failure_cases:
                    self.failure_cases.append((i,j))
                    self.failureLSP.setdefault(len(self.failure_cases)-1,None)
        
        for p in range(0,len(self.failure_cases)):
            composited_LSP = [1] * (len(self.composited_link_set))
            if (type(self.failure_cases[p]) == int):
                downstream_switches = list(self.control_path_tree[self.failure_cases[p]]["nodes"])
                affected_switch = self.failure_cases[p]
                for i in range(0,len(self.composited_link_set)):
                    if (self.composited_link_set[i][0] == affected_switch or self.composited_link_set[i][1] == affected_switch):
                        composited_LSP[i] = 0
                    elif (self.composited_link_set[i][0] in downstream_switches and self.composited_link_set[i][1] in downstream_switches):
                        composited_LSP[i] = 0
                control_path = True
            elif (type(self.failure_cases[p]) == tuple):
                node_i,node_j = self.failure_cases[p]
                control_path = False
                if (node_i == self.control_path_tree[node_j]["root"]):
                    control_path = True
                    downstream_switches = [node_j]+list(self.control_path_tree[node_j]["nodes"])
                elif (node_j == self.control_path_tree[node_i]["root"]):
                    control_path = True
                    downstream_switches = [node_i]+list(self.control_path_tree[node_j]["nodes"])
                for i in range(0,len(self.composited_link_set)):
                    if ((self.composited_link_set[i][0],self.composited_link_set[i][1]) ==  self.failure_cases[p] or (self.composited_link_set[i][1],self.composited_link_set[i][0]) == self.failure_cases[p]):
                        composited_LSP[i] = 0
                    elif (control_path == True and self.composited_link_set[i][0] in downstream_switches and self.composited_link_set[i][1] in downstream_switches):
                        composited_LSP[i] = 0
            if (control_path == True):
                self.control_failure_cases.append(self.failure_cases[p])
            self.failureLSP[p] = composited_LSP
        return

    def MRT_Algorithm(self, topology, f, UCS, CS):
        RS = list(CS)
        URS = list(UCS)
        KOS = []
        MS = []
        FRCTime = 0
        RFPSwitch = {0: {"root":-1,"nodes":[]}}
        for i in self.switch_information:
            if (i != 0 and i in RS):
                RFPSwitch.setdefault(i,{"root": self.control_path_tree[i]["root"], "nodes":[]})
            elif (i != 0 and i in URS):
                RFPSwitch.setdefault(i,{"root":None,"nodes":[]})
        while (True):
            if (FRCTime == 0):
                for s in URS:
                    if (0 in topology[s] and s in topology[0]):
                        RFPSwitch[s]["root"] = 0
                        MS.append(s)
            elif (FRCTime > 0):
                MS = []
                for s in URS:
                    if (s in KOS):
                        RFPSwitch[s]["root"] = self.control_path_tree[s]["root"]
                        MS.append(s)
                    else:
                        for n in RS:
                            if (n in topology[s] and s in topology[n]):
                                RFPSwitch[s]["root"] = n
                                MS.append(s)
                                break
                KOS = []
                MS = sorted(MS, key=lambda x: len(self.control_path_tree[x]["nodes"]))
                for idx in range(0,len(MS)):
                    for n in self.control_path_tree[MS[idx]]["nodes"]:
                        if (not(n in MS) and not(n in KOS)):
                            KOS.append(n)
            for s in MS:
                RS.append(s)
                URS.remove(s)
            FRCTime+=1
            if (len(URS) == 0):
                break
        for i in RFPSwitch:
            root = RFPSwitch[i]["root"]
            while (root != -1):
                RFPSwitch[root]["nodes"].append(i)
                root = RFPSwitch[root]["root"]
        return RFPSwitch
    
    def recoveryPath_calculator(self):
        self.recovery_path_tree = {}
        for fcid in range(0,len(self.failure_cases)):
            f = self.failure_cases[fcid]
            CS = []
            topology = copy.deepcopy(self.topology)
            if (type(f) == int):
                UCS = list(self.control_path_tree[f]["nodes"])
                for i in topology[f]:
                    del topology[i][f]
                del topology[f]
                for i in self.switch_information:
                    if (i != 0 and i != f and i not in UCS):
                        CS.append(i)
                mrtta_flag = False if (len(UCS) == 0) else True
            elif (type(f) == tuple):
                if (self.control_path_tree[f[0]]['root'] == f[1] or self.control_path_tree[f[1]]['root'] == f[0]):
                    del topology[f[0]][f[1]]
                    del topology[f[1]][f[0]]
                    if (f[0] == self.control_path_tree[f[1]]["root"]):
                        UCS = [f[1]]+list(self.control_path_tree[f[1]]["nodes"])
                    elif (f[1] == self.control_path_tree[f[0]]["root"]):
                        UCS = [f[0]]+list(self.control_path_tree[f[0]]["nodes"])
                    for i in self.switch_information:
                        if (i != 0 and i not in UCS):
                            CS.append(i)
                    mrtta_flag = True
                else:
                    mrtta_flag = False
            if (mrtta_flag == True):
                RFPSwitch = self.MRT_Algorithm(topology, f, UCS, CS)
                self.recovery_path_tree.setdefault(fcid, {"UCS":list(UCS), "tree":RFPSwitch})
            else:
                self.recovery_path_tree.setdefault(fcid, {"UCS":[], "tree":copy.deepcopy(self.control_path_tree)})   
        return 

    def FREntries_generator (self):
        self.recovery_path_entries = {}
        for r in self.recovery_path_tree:
            failure_case = self.failure_cases[r]
            tree = self.recovery_path_tree[r]["tree"]
            UCS = self.recovery_path_tree[r]["UCS"]
            recovery_paths = {}
            recovery_paths_schedule = []
            for i in UCS:
                path = [i]
                root = tree[i]["root"]
                while (root != -1):
                    path.insert(0,root)
                    root = tree[root]["root"]
                recovery_paths.setdefault(i, path)
            insert_list = []
            delete_list = []
            insert_entries = {}
            delete_entries = {}
            ovs_configuration_update = []
            cu_dict = {}
            recovery_schedules = []
            configuration_update = []
            if (len(recovery_paths.keys()) > 0):
                recovery_paths_schedule = sorted(recovery_paths.keys(), key = lambda x: len(recovery_paths[x]))
                # print(recovery_paths_schedule)
                for sw_id in recovery_paths_schedule:
                    switch_ip = self.switch_information[sw_id].switch_ip
                    control_ip = self.control_socket['ip'][0]
                    recovery_path = recovery_paths[sw_id]
                    original_path = self.switch_information[sw_id].control_path
                    ovs_configuration_update.append([switch_ip, control_ip, self.topology[recovery_path[0]][recovery_path[1]]])
                    if (recovery_path[-2] not in cu_dict):
                        cu_dict.setdefault(recovery_path[-2], [(recovery_path[-2], recovery_path[-1], self.topology[recovery_path[-2]][recovery_path[-1]], self.topology[recovery_path[-1]][recovery_path[-2]])])
                    else:
                        cu_dict[recovery_path[-2]].append((recovery_path[-2], recovery_path[-1], self.topology[recovery_path[-2]][recovery_path[-1]], self.topology[recovery_path[-1]][recovery_path[-2]]))
                    for p in range(1,len(recovery_path)-1):  
                        if (recovery_path[p] not in insert_list):
                            insert_list.append(recovery_path[p])
                        p4info_helper = self.switch_information[recovery_path[p]].p4info_helper  
                        action = 1 if (recovery_path[p] in original_path) else 0
                        entries = self._write_arp_forwarding_rules(action, p4info_helper, switch_ip, 1, 1, self.topology[recovery_path[p]][recovery_path[p+1]])
                        entries += self._write_ipv4_forwarding_rules(action, p4info_helper, switch_ip, 0, 1, 1, self.topology[recovery_path[p]][recovery_path[p+1]])
                        if (recovery_path[p] not in insert_entries):
                            insert_entries.setdefault(recovery_path[p], entries)
                        else:
                            insert_entries[recovery_path[p]] += entries
                    
                    for p in range(1,len(original_path)-1):
                        if (original_path[p] == failure_case):
                            pass
                        elif (original_path[p] not in recovery_path):
                            action = 2
                            if (original_path[p] not in delete_list):
                                delete_list.append(original_path[p])
                            p4info_helper = self.switch_information[original_path[p]].p4info_helper
                            entries = self._write_arp_forwarding_rules(action, p4info_helper, switch_ip, 1, 1, self.topology[original_path[p]][original_path[p+1]])
                            entries += self._write_ipv4_forwarding_rules(action, p4info_helper, switch_ip, 0, 1, 1, self.topology[original_path[p]][original_path[p+1]])
                            if (original_path[p] not in delete_entries):
                                delete_entries.setdefault(original_path[p], entries)
                            else:
                                delete_entries[original_path[p]] += entries
                
                schedules = [0]+[i for i in insert_list if (i not in UCS)]
                recovery_schedules.append(schedules)
                ucs_insert_entries_list = [i for i in insert_list if (i in UCS)]
                length = []
                for i in ucs_insert_entries_list:
                    count = 0
                    for p in recovery_paths[i]:
                        if (p in UCS):
                            count += 1
                    length.append(count)
                while(len(ucs_insert_entries_list)> 0):
                    value = min(length)
                    valueList = [ucs_insert_entries_list[x] for x in range(len(length)) if  length[x] == value]
                    recovery_schedules.append(valueList)
                    for i in valueList:
                        ucs_insert_entries_list.remove(i)
                        length.remove(value)
                # recovery_schedules.append([recovery_paths_schedule[-1]])
                for rs in recovery_schedules:
                    configuration_update_information = []
                    for sw_id in rs:
                        if (sw_id in cu_dict):
                            configuration_update_information += cu_dict[sw_id]
                    configuration_update.append(self.configuration_update_message_generator(configuration_update_information))
            self.recovery_path_entries.setdefault(r, {
                "ovs_configuration_update":ovs_configuration_update, 
                "recovery_schedules":recovery_schedules, 
                "insert_entries":insert_entries, 
                "delete_entries":delete_entries, 
                "configuration_update":configuration_update,
                "recovery_paths": recovery_paths
            })
        return 
    
    def duplicateLSP_checker_planner(self):
        graph = nx.DiGraph()
        control_ip = self.control_socket['ip'][1]
        for i in self.topology:
            for j in self.topology[i]:
                graph.add_edge(i,j)
        for sw_id in self.switch_information:
            if (sw_id != 0):
                node_i = sw_id
                node_j = self.control_path_tree[sw_id]["root"]
                if ((node_i, node_j) in self.failure_cases):
                    lfid = self.failure_cases.index((node_i, node_j))
                elif ((node_j, node_i) in self.failure_cases):
                    lfid = self.failure_cases.index((node_j, node_i))
                nfid = self.failure_cases.index(node_i)
                if (self.failureLSP[lfid] == self.failureLSP[nfid]):
                    copy_graph = graph.copy()
                    copy_graph.remove_edge(node_i, node_j)
                    copy_graph.remove_edge(node_j, node_i)
                    if (nx.has_path(copy_graph, 0, sw_id)):
                        path = nx.shortest_path(copy_graph, source=0, target=sw_id)
                        switch_ip = self.switch_information[sw_id].switch_ip
                        self.ovs_command(1, switch_ip, control_ip, self.topology[path[0]][path[1]])
                        self.switch_information[sw_id].node_detection_path = list(path)
                        for i in range(1, len(path)-1):
                            p4info_helper = self.switch_information[path[i]].p4info_helper
                            entries = self._write_ipv4_forwarding_rules(0, p4info_helper, switch_ip, 1, 1, 7, self.topology[path[i]][path[i+1]])
                            entries = self._write_ipv4_forwarding_rules(0, p4info_helper, control_ip, 1, 1, 7, self.topology[path[i]][path[i-1]])
                            self.switch_information[path[i]].grpc_connection.WriteTableEntry(entries)
    
    # Functions for controlling P4 inband network
    def initialization (self):
        try:
            start_time = time()
            while (time() - start_time < 15):
                self.switch_discovery()
                sleep(self.switch_discovery_time_interval)
                pass
        except(KeyboardInterrupt):
            return
    
    def network_failure_planner (self): 
        start_time = time()
        while (time()-start_time < 30):
            self.network_monitoring()
            sleep(self.network_monitoring_time_interval)
        for i in self.topology:
            print ("%d: "%i, end="")
            for j in self.topology[i]:
                print ("%d:%d "%(j,self.topology[i][j]), end="")
            print (" ")
        self.failureLSP_calculator()
        self.recoveryPath_calculator()
        self.FREntries_generator()
        self.duplicateLSP_checker_planner()
        start_time = time()
        while (time()-start_time < 5):
            for sw_id in self.switch_information: self.switch_information[sw_id].node_detection = 0
            self.composited_LSP = [0] * len(self.composited_LSP)
            self.direct_LSP = [0] * len(self.direct_LSP)
            self.network_monitoring()
            sleep(self.network_monitoring_time_interval)
        self.record_orginal_state()
        for f in self.recovery_path_tree:
            if (len(self.recovery_path_entries[f]["recovery_paths"]) > 0):
                print ("%s: "%(str(self.failure_cases[f])))
                for i in self.recovery_path_entries[f]["recovery_paths"]:
                    print ("%d\t%s, "%(i, str(self.recovery_path_entries[f]["recovery_paths"][i])))
        return
    
    def failure_detection_and_recovery(self):
        start_time = time()
        for sw_id in self.switch_information: self.switch_information[sw_id].node_detection = 0
        self.direct_LSP = [0] * len(self.direct_LSP)
        direct_LSP_list = [[0] * len(self.direct_LSP)] * 3
        detect_failure_flag = 0
        while (time()-start_time < 10):
            st = time()
            Thread(target=self.network_monitoring).start()
            direct_LSP_list.append(self.direct_LSP)
            direct_LSP_list.pop(0)
            node_detections = {}
            self.direct_LSP = [0] * len(self.direct_LSP)
            for sw_id in self.switch_information:
                node_detections.setdefault(sw_id, int(self.switch_information[sw_id].node_detection))
                self.switch_information[sw_id].node_detection = 0
            if (time()-start_time > 1):
                if (detect_failure_flag == 0):
                    if (0 in direct_LSP_list[-1]):
                        detect_failure_flag = 1
                else:
                    if (0 not in direct_LSP_list[-1]):
                        detect_failure_flag = 0
                    else:
                        detect_failure_flag += 1
                if (detect_failure_flag > 2):
                    result = [0 if (sum(x) == 0) else 1 for x in zip(*direct_LSP_list)]
                    curr_composited_LSP = [0]*len(self.composited_link_set)
                    for r in range(len(result)):
                        if (result[r] == 1):
                            nodeA,nodeB = self.direct_link_set[r]
                            if ((nodeA, nodeB) in self.composited_link_set):
                                curr_composited_LSP[self.composited_link_set.index((nodeA, nodeB))] = 1
                            elif ((nodeB, nodeA) in self.composited_link_set):
                                curr_composited_LSP[self.composited_link_set.index((nodeB, nodeA))] = 1
                    if (0 not in curr_composited_LSP):
                        sleep(self.network_monitoring_time_interval - (time()-st))
                        continue
                    failure_id = [ p for p in self.failureLSP if (curr_composited_LSP == self.failureLSP[p])]
                    single_failure = False
                    if (len(failure_id) > 0):
                        self.configuration_network_flag = True
                        if (len(failure_id)==1):
                            failure_case_id = failure_id[0]
                            single_failure = True
                        elif (len(failure_id) >= 2):
                            link_case_id = node_case_id = None
                            for s in failure_id:
                                if (type(self.failure_cases[s]) == tuple):
                                    link_case_id = s
                                elif (type(self.failure_cases[s]) == int):
                                    node_case_id = s
                            if (not (link_case_id == node_case_id == None)): 
                                if (self.failure_cases[node_case_id] in self.failure_cases[link_case_id] 
                                    and self.control_path_tree[self.failure_cases[node_case_id]]["root"] in self.failure_cases[link_case_id]):
                                    single_failure = True
                                    if (node_detections[self.failure_cases[node_case_id]] > 0):
                                        failure_case_id = link_case_id
                                    else:
                                        failure_case_id = node_case_id
                    self.direct_LSP = direct_LSP_list[-1]
                    if (single_failure == True):
                        failure_case = self.failure_cases[failure_case_id]
                        detection_time = time()-start_time
                        recovery_time = 0
                        if (len(self.recovery_path_tree[failure_case_id]['UCS']) > 0):
                            single_failure, recovery_time = self.single_failure_recovery(failure_case_id)
                        if (single_failure == True):
                            if (type(failure_case) == int):
                                self.control_path_tree = copy.deepcopy(self.recovery_path_tree[failure_case_id]['tree'])
                                self.switch_information[failure_case].grpc_connection.shutdown()
                                self.delete_control_path(failure_case)
                                del self.switch_information[failure_case]
                        else:
                            failure_case_id = -1  # -1 if Multiple Failure detection during single failure recovery 
                        self.configuration_network_flag = False
                        return failure_case_id, detection_time, recovery_time
                    else:
                        print ("Multiple Failure")
                        self.configuration_network_flag = True
                        CS = []
                        UCS = []
                        for i in range(len(self.direct_LSP)):
                            if (self.direct_LSP[i] == 1):
                                if (self.direct_link_set[i][0] != 0 and self.direct_link_set[i][0] not in CS):
                                    CS.append(self.direct_link_set[i][0])
                        for sw_id in self.switch_information:
                            if (sw_id != 0 and sw_id not in CS):
                                UCS.append(sw_id)
                        detection_time = time()-start_time
                        recovery_time = self.multiple_failure_recovery(time(), CS, UCS)
                        self.configuration_network_flag = False
                        return -1, detection_time, recovery_time
            sleep(self.network_monitoring_time_interval - (time()-st))
        return None, None, None
     
    def reset_recovery_paths (self, failure_case_id, recovery_level):
        recovery_path_tree = self.recovery_path_tree[failure_case_id]
        tree = recovery_path_tree["tree"]
        UCS = recovery_path_tree["UCS"]
        recovery_paths = {}
        recovery_paths_schedule = []
        for i in UCS:
            path = [i]
            root = tree[i]["root"]
            while (root != -1):
                path.insert(0,root)
                root = tree[root]["root"]
            recovery_paths.setdefault(i, path)
        delete_list = []
        delete_entries = {}
        recovery_paths_schedule = sorted(recovery_paths.keys(), key = lambda x: len(recovery_paths[x]))
        for sw_id in recovery_paths_schedule:
            switch_ip = self.switch_information[sw_id].switch_ip
            control_ip = self.control_socket['ip'][0]
            recovery_path = recovery_paths[sw_id]
            original_path = self.switch_information[sw_id].control_path
            for p in range(1,len(recovery_path)-1):  
                if (recovery_path[p] not in original_path):
                    if (recovery_path[p] not in delete_list):
                        delete_list.append(recovery_path[p])
                    p4info_helper = self.switch_information[recovery_path[p]].p4info_helper  
                    action = 2
                    entries = self._write_arp_forwarding_rules(action, p4info_helper, switch_ip, 1, 1, self.topology[recovery_path[p]][recovery_path[p+1]])
                    entries += self._write_ipv4_forwarding_rules(action, p4info_helper, switch_ip, 0, 1, 1, self.topology[recovery_path[p]][recovery_path[p+1]])
                    if (recovery_path[p] not in delete_entries):
                        delete_entries.setdefault(recovery_path[p], entries)
                    else:
                        delete_entries[recovery_path[p]] += entries
        
        recovery_schedules = [[i for i in delete_list if (i not in UCS)]]
        ucs_delete_entries_list = [i for i in delete_list if (i in UCS)]
        length = []
        for i in ucs_delete_entries_list:
            count = 0
            for p in recovery_paths[i]:
                if (p in UCS):
                    count += 1
            length.append(count)
        while(len(ucs_delete_entries_list)> 0):
            schedule = []
            value = min(length)
            valueList = [ucs_delete_entries_list[x] for x in range(len(length)) if  length[x] == value]
            recovery_schedules.append(valueList)
            for i in valueList:
                idx = ucs_delete_entries_list.index(i)
                ucs_delete_entries_list.pop(idx)
                length.pop(idx)
        # print (recovery_schedules)
        for i in range(len(recovery_schedules)):
            if (i < recovery_level):
                thread_list = {}
                rs = recovery_schedules[i]
                for sw_id in rs:
                    thread_list.setdefault(sw_id, Thread(target=self.switch_information[sw_id].grpc_connection.WriteTableEntry, args=(delete_entries[sw_id], )))
                    thread_list[sw_id].start()
                for t in thread_list:
                    thread_list[t].join()
        
    def single_failure_recovery (self, failure_case_id):
        start_time = time()
        recovery_path_entries = self.recovery_path_entries[failure_case_id]
        ovs_configuration_update = recovery_path_entries["ovs_configuration_update"] 
        recovery_schedules = recovery_path_entries["recovery_schedules"]
        insert_entries = recovery_path_entries["insert_entries"] 
        configuration_update = recovery_path_entries["configuration_update"]
        delete_entries = recovery_path_entries["delete_entries"] 
        recovery_paths = recovery_path_entries["recovery_paths"] 
        self.recovery_node_list = list(recovery_paths.keys())
        for i in ovs_configuration_update:
            Thread(target=self.ovs_command, args=(1, i[0], i[1], i[2], )).start()
        multiple_failure_detected = False
        for i in range(0,len(recovery_schedules)):
            rs = recovery_schedules[i]
            self.configuration_update_waiting_list = copy.deepcopy(configuration_update[i])
            result = self.send_configuration_update_message()
            if (result == True):
                thread_list = {}
                for sw_id in rs:
                    if (sw_id in insert_entries):
                        thread_list.setdefault(sw_id, Thread(target=self.switch_information[sw_id].grpc_connection.WriteTableEntry, args=(insert_entries[sw_id], )))
                        thread_list[sw_id].start()
                if (len(thread_list) > 0):
                    for t in thread_list:
                        thread_list[t].join()
                else:
                    sleep(0.002)
            else:
                multiple_failure_detected = True
        if (multiple_failure_detected == True):
            print ("Multiple Failure")
            CS = []
            UCS = []
            self.reset_recovery_paths (failure_case_id, i)
            for i in range(len(self.direct_LSP)):
                if (self.direct_LSP[i] == 1):
                    if (self.direct_link_set[i][0] != 0 and self.direct_link_set[i][0] not in CS):
                        CS.append(self.direct_link_set[i][0])
            for sw_id in self.switch_information:
                if (sw_id != 0 and sw_id not in CS):
                    UCS.append(sw_id)
            print ("controlled_switch: %s"%str(CS))
            print ("uncontrolled_switch: %s"%str(UCS))
            return False, self.multiple_failure_recovery(start_time, CS, UCS)
        else:
            for sw_id in self.recovery_node_list:
                Payload = pack("!BBI", 0x1, 0x3, sw_id)
                self.control_socket["socket"][0].sendto(Payload, (self.switch_information[sw_id].switch_ip,0))
            while (len(self.recovery_node_list) > 0):
                sleep(0.001)
            finish_time = time()
            for sw_id in delete_entries:
                self.switch_information[sw_id].grpc_connection.WriteTableEntry(delete_entries[sw_id])
            for sw_id in recovery_paths:
                self.switch_information[sw_id].control_path = list(recovery_paths[sw_id])
            return True, (finish_time - start_time)
    
    def multiple_failure_recovery (self, start_time, CS, UCS):
        curr_link_status = list(self.direct_LSP)
        control_ip = self.control_socket['ip'][0]
        recovery_time = time() - start_time
        print ("Controlled switch: %s"%str(CS))
        print ("Uncontrolled switch: %s"%str(UCS))
        while True:
            active_links = [i for i in range(len(curr_link_status)) if (self.direct_link_set[i][1] in UCS and curr_link_status[i] == 1)]
            if (len(active_links) == 0):
                print ("No switch can be recovered. Finish")
                return recovery_time
            else:
                cu_dict = {}
                ovs_configuration_update = []
                insert_list = []
                insert_entries = {}
                delete_entries = {}
                recovery_paths = {}
                for l in active_links:
                    sw_id = self.direct_link_set[l][1]
                    rsw_id = self.direct_link_set[l][0]
                    if (sw_id not in CS and sw_id not in self.switch_information[rsw_id].control_path):
                        CS.append(sw_id)
                        UCS.remove(sw_id)
                        original_path = self.switch_information[sw_id].control_path
                        recovery_path  = self.switch_information[rsw_id].control_path+[sw_id]
                        switch_ip = self.switch_information[sw_id].switch_ip
                        self.switch_information[sw_id].control_path = recovery_path
                        recovery_paths.setdefault(sw_id, recovery_path)
                        print (sw_id, recovery_path)
                        if (recovery_path[-2] not in cu_dict):
                            cu_dict.setdefault(recovery_path[-2], [(recovery_path[-2], recovery_path[-1], self.topology[recovery_path[-2]][recovery_path[-1]], self.topology[recovery_path[-1]][recovery_path[-2]])])
                        else:
                            cu_dict[recovery_path[-2]].append((recovery_path[-2], recovery_path[-1], self.topology[recovery_path[-2]][recovery_path[-1]], self.topology[recovery_path[-1]][recovery_path[-2]]))
                        ovs_configuration_update.append([switch_ip, control_ip, self.topology[recovery_path[0]][recovery_path[1]]])
                        for p in range(1,len(recovery_path)-1):  
                            if (recovery_path[p] not in insert_list):
                                insert_list.append(recovery_path[p])
                            p4info_helper = self.switch_information[recovery_path[p]].p4info_helper  
                            action = 1 if (recovery_path[p] in original_path) else 0
                            entries = self._write_arp_forwarding_rules(action, p4info_helper, switch_ip, 1, 1, self.topology[recovery_path[p]][recovery_path[p+1]])
                            entries += self._write_ipv4_forwarding_rules(action, p4info_helper, switch_ip, 0, 1, 1, self.topology[recovery_path[p]][recovery_path[p+1]])
                            if (recovery_path[p] not in insert_entries):
                                insert_entries.setdefault(recovery_path[p], entries)
                            else:
                                insert_entries[recovery_path[p]] += entries
                        
                        for p in range(1,len(original_path)-1):
                            if (original_path[p] in UCS):
                                pass
                            elif (original_path[p] not in recovery_path):
                                action = 2
                                p4info_helper = self.switch_information[original_path[p]].p4info_helper
                                entries = self._write_arp_forwarding_rules(action, p4info_helper, switch_ip, 1, 1, self.topology[original_path[p]][original_path[p+1]])
                                entries += self._write_ipv4_forwarding_rules(action, p4info_helper, switch_ip, 0, 1, 1, self.topology[original_path[p]][original_path[p+1]])
                                if (original_path[p] not in delete_entries):
                                    delete_entries.setdefault(original_path[p], entries)
                                else:
                                    delete_entries[original_path[p]] += entries
                
                recovery_schedules = [[i for i in insert_list if (i not in UCS)]]
                ucs_insert_entries_list = [i for i in insert_list if (i in UCS)]
                length = []
                for i in ucs_insert_entries_list:
                    count = 0
                    for p in recovery_paths[i]:
                        if (p in UCS):
                            count += 1
                    length.append(count)
                while(len(ucs_insert_entries_list)> 0):
                    value = min(length)
                    valueList = [ucs_insert_entries_list[x] for x in range(len(length)) if  length[x] == value]
                    recovery_schedules.append(valueList)
                    for i in valueList:
                        idx = ucs_insert_entries_list.index(i)
                        ucs_insert_entries_list.pop(idx)
                        length.pop(idx)
                configuration_update = []
                for rs in recovery_schedules:
                    configuration_update_information = []
                    for sw_id in rs:
                        if (sw_id in cu_dict):
                            configuration_update_information += cu_dict[sw_id]
                    configuration_update.append(self.configuration_update_message_generator(configuration_update_information))
                
                for i in ovs_configuration_update:
                    self.ovs_command(1, i[0], i[1], i[2])
                
                for i in range(0,len(recovery_schedules)):
                    rs = recovery_schedules[i]
                    self.configuration_update_waiting_list = copy.deepcopy(configuration_update[i])
                    result = self.send_configuration_update_message()
                    print (result)
                    thread_list = {}
                    for sw_id in rs:
                        thread_list.setdefault(sw_id, Thread(target=self.switch_information[sw_id].grpc_connection.WriteTableEntry, args=(insert_entries[sw_id], )))
                        thread_list[sw_id].start()
                    for t in thread_list:
                        thread_list[t].join()
                for sw_id in delete_entries:
                    self.switch_information[sw_id].grpc_connection.WriteTableEntry(delete_entries[sw_id])

                print ("after thread wait...", time()-start_time)
                print ("Controlled switch: %s"%str(CS))
                print ("Uncontrolled switch: %s"%str(UCS))
                recovery_time = time() - start_time
                self.network_monitoring()
                sleep(self.network_monitoring_time_interval)
                curr_link_status = list(self.direct_LSP)

    def delete_control_path(self, sw_id):
        switch_ip = self.switch_information[sw_id].switch_ip
        control_ip = self.control_socket['ip'][0]
        path = self.switch_information[sw_id].control_path
        self.ovs_command(2, switch_ip, control_ip, self.topology[path[0]][path[1]])
        for i in range(1,len(path)-1):
            if (path[i] in self.switch_information):
                entries = self._write_arp_forwarding_rules(2, self.switch_information[path[i]].p4info_helper,  switch_ip, 1, 1, self.topology[path[i]][path[i+1]])
                entries += self._write_ipv4_forwarding_rules(2, self.switch_information[path[i]].p4info_helper,  switch_ip, 0, 1, 1, self.topology[path[i]][path[i+1]])
                self.switch_information[path[i]].grpc_connection.WriteTableEntry(entries)
        path = self.switch_information[sw_id].node_detection_path
        if (len(path) > 0):
            control_ip = self.control_socket['ip'][1]
            self.ovs_command(2, switch_ip, control_ip, self.topology[path[0]][path[1]])
            for i in range(1,len(path)-1):
                if (path[i] in self.switch_information):
                    entries = self._write_ipv4_forwarding_rules(2, self.switch_information[path[i]].p4info_helper, switch_ip, 1, 1, 7, self.topology[path[i]][path[i+1]])
                    entries = self._write_ipv4_forwarding_rules(2, self.switch_information[path[i]].p4info_helper, control_ip, 1, 1, 7, self.topology[path[i]][path[i-1]])
                    self.switch_information[path[i]].grpc_connection.WriteTableEntry(entries)
        for i in self.topology[sw_id]:
            if (i != 0):
                entries = self._write_cu_switch_port_rules(2, self.switch_information[i].p4info_helper, self.topology[i][sw_id])
                self.switch_information[i].grpc_connection.WriteTableEntry(entries)

    def kill_controller(self):
        self.Process_Stop_Flag = True
        print ("Killing thread services")
        for i in self.switch_information:
            if (i!=0):
                self.switch_information[i].grpc_connection.shutdown()
        self.P4IBN_raw_socket.close()
        for s in self.control_socket["socket"]: 
            s.close()

    # Functions for testing 
    # Recording orginal flow entries/ setting 
    def record_orginal_state (self):
        for sw_id in self.switch_information:
            if (sw_id != 0):
                self.orginal_switch_information.setdefault(sw_id, {"control_path": list(self.switch_information[sw_id].control_path), "node_detection_path": list(self.switch_information[sw_id].node_detection_path), "low":0})
        self.orginal_control_path_tree = copy.deepcopy(self.control_path_tree)
    # Reset testbed 
    def reset_testbed(self, failure_id):
        failure_case = self.failure_cases[failure_id]
        if (type(failure_case) == int):
            sw_id = failure_case
            switch_ip = self.switch_information[sw_id].switch_ip
            control_ip = self.control_socket['ip'][0]
            entries = []
            path = self.switch_information[sw_id].control_path
            for i in self.topology[sw_id]:
                if (i != 0 and path[-2] != i):
                    entries += self._write_cu_switch_port_rules(0, self.switch_information[sw_id].p4info_helper, self.topology[sw_id][i])
                    entry = self._write_cu_switch_port_rules(0, self.switch_information[i].p4info_helper, self.topology[i][sw_id])
                    self.switch_information[i].grpc_connection.WriteTableEntry(entry)
            self.switch_information[sw_id].grpc_connection.WriteTableEntry(entries)
            if (not(self.orginal_switch_information[sw_id]["control_path"] == self.switch_information[sw_id].control_path)):
                control_path = self.orginal_switch_information[sw_id]["control_path"]
                original_path = self.switch_information[sw_id].control_path
                self.ovs_command(1, switch_ip, control_ip, self.topology[control_path[0]][control_path[1]])
                for i in range(1, len(control_path)-1):
                    action = 0 if (control_path[i] not in original_path) else 1
                    entries = self._write_arp_forwarding_rules(action, self.switch_information[control_path[i]].p4info_helper, switch_ip, 1, 1, self.topology[control_path[i]][control_path[i+1]])
                    entries += self._write_ipv4_forwarding_rules(action, self.switch_information[control_path[i]].p4info_helper, switch_ip, 0, 1, 1, self.topology[control_path[i]][control_path[i+1]])
                    self.switch_information[control_path[i]].grpc_connection.WriteTableEntry(entries)
                for i in range(1, len(original_path)-1):
                    if (original_path[i] not in control_path):
                        action = 2
                        entries = self._write_arp_forwarding_rules(action, self.switch_information[original_path[i]].p4info_helper, switch_ip, 1, 1, self.topology[original_path[i]][original_path[i+1]])
                        entries += self._write_ipv4_forwarding_rules(action, self.switch_information[original_path[i]].p4info_helper, switch_ip, 0, 1, 1, self.topology[original_path[i]][original_path[i+1]], 0)
                        self.switch_information[original_path[i]].grpc_connection.WriteTableEntry(entries)
                self.configuration_update_waiting_list = self.configuration_update_message_generator([(control_path[-2], control_path[-1], self.topology[control_path[-2]][control_path[-1]], self.topology[control_path[-1]][control_path[-2]])])
                result = self.send_configuration_update_message()
                self.switch_information[sw_id].control_path = control_path
            control_ip = self.control_socket['ip'][1]
            path = self.orginal_switch_information[sw_id]["node_detection_path"]
            if (len(path) > 0):
                self.switch_information[sw_id].node_detection_path = list(path)
                self.ovs_command(1, switch_ip, control_ip, self.topology[path[0]][path[1]])
                for i in range(1,len(path)-1):
                    entries = self._write_ipv4_forwarding_rules(0, self.switch_information[path[i]].p4info_helper, switch_ip, 1, 1, 7, self.topology[path[i]][path[i+1]])
                    entries = self._write_ipv4_forwarding_rules(0, self.switch_information[path[i]].p4info_helper, control_ip, 1, 1, 7, self.topology[path[i]][path[i-1]])
                    self.switch_information[path[i]].grpc_connection.WriteTableEntry(entries)
            for o_sw_id in self.orginal_switch_information:
                if (o_sw_id != sw_id and len(self.switch_information[o_sw_id].node_detection_path) > 0 and sw_id in self.orginal_switch_information[o_sw_id]['node_detection_path']):
                    switch_ip = self.switch_information[o_sw_id].switch_ip
                    path = self.orginal_switch_information[o_sw_id]['node_detection_path']
                    i = path.index(sw_id)
                    entries = self._write_ipv4_forwarding_rules(0, self.switch_information[path[i]].p4info_helper, switch_ip, 1, 1, 7, self.topology[path[i]][path[i+1]])
                    entries = self._write_ipv4_forwarding_rules(0, self.switch_information[path[i]].p4info_helper, control_ip, 1, 1, 7, self.topology[path[i]][path[i-1]])
                    self.switch_information[path[i]].grpc_connection.WriteTableEntry(entries)
        self.control_path_tree = copy.deepcopy(self.orginal_control_path_tree)
        tree = self.recovery_path_tree[failure_id]["tree"]
        UCS = self.recovery_path_tree[failure_id]["UCS"]
        recovery_paths = {}
        for i in UCS:
            path = [i]
            root = tree[i]["root"]
            while (root != -1):
                path.insert(0,root)
                root = tree[root]["root"]
            recovery_paths.setdefault(i, path)
        reset_paths = {}
        for sw_id in UCS:
            reset_paths.setdefault(sw_id, self.orginal_switch_information[sw_id]["control_path"])
        sorted_sw_id = sorted(reset_paths.keys(), key=lambda x: len(reset_paths[x]))
        for sw_id in sorted_sw_id:
            control_path = reset_paths[sw_id]
            original_path = recovery_paths[sw_id]
            switch_ip = self.switch_information[sw_id].switch_ip
            control_ip = self.control_socket['ip'][0]
            self.ovs_command(1, switch_ip, control_ip, self.topology[control_path[0]][control_path[1]])
            self.switch_information[sw_id].control_path = control_path
            self.configuration_update_waiting_list = self.configuration_update_message_generator([(control_path[-2], control_path[-1], self.topology[control_path[-2]][control_path[-1]], self.topology[control_path[-1]][control_path[-2]])])
            result = self.send_configuration_update_message()
            for i in range(1, len(control_path)-1):
                action = 1 if (control_path[i] in original_path) else 0
                entries = self._write_arp_forwarding_rules(action, self.switch_information[control_path[i]].p4info_helper, switch_ip, 1, 1, self.topology[control_path[i]][control_path[i+1]])
                entries += self._write_ipv4_forwarding_rules(action, self.switch_information[control_path[i]].p4info_helper, switch_ip, 0, 1, 1, self.topology[control_path[i]][control_path[i+1]])
                self.switch_information[control_path[i]].grpc_connection.WriteTableEntry(entries)
            for i in range(1, len(original_path)-1):
                if (original_path[i] not in control_path):
                    entries = self._write_arp_forwarding_rules(2, self.switch_information[original_path[i]].p4info_helper, switch_ip, 1, 1, self.topology[original_path[i]][original_path[i+1]])
                    entries += self._write_ipv4_forwarding_rules(2, self.switch_information[original_path[i]].p4info_helper, switch_ip, 0, 1, 1, self.topology[original_path[i]][original_path[i+1]])
                    self.switch_information[original_path[i]].grpc_connection.WriteTableEntry(entries)
        return 
    # Flow entries of background traffic
    def background_traffic_path_configure(self, hostA, hostB, nodeA, nodeB):
        p4_table_entries = self._write_arp_forwarding_rules(0, self.switch_information[nodeA].p4info_helper, hostA, 1, 0, self.topology[nodeA][nodeB])
        p4_table_entries += self._write_ipv4_forwarding_rules(0, self.switch_information[nodeA].p4info_helper, hostA, 0, 1, 0, self.topology[nodeA][nodeB])
        p4_table_entries = self._write_arp_forwarding_rules(0, self.switch_information[nodeA].p4info_helper, hostB, 1, 0, 250)
        p4_table_entries += self._write_ipv4_forwarding_rules(0, self.switch_information[nodeA].p4info_helper, hostB, 0, 1, 0, 250)
        self.switch_information[nodeA].grpc_connection.WriteTableEntry(p4_table_entries)
        return 
    


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import socket
import json
import struct
from time import time, sleep

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

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self._threads = []
        self.datapath = {}
        self.testbed_datapath = {"1": "0xeb74cc37ab011005", "2": "0xeb747072cffe09b2"}
        self.testbed_control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.testbed_control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.testbed_control_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
        self.testbed_control_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.testbed_control_socket.bind(("0.0.0.0", 50000))
        self.testbed_control_socket.listen(1)
        self.flow_control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.flow_control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.flow_control_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
        self.flow_control_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.flow_control_socket.bind(("0.0.0.0", 50050))
        self.flow_control_socket.listen(1)
        self.topology = {}
        self.mapping_links = []
        self.tables_ids =[]
        
    def testbed_control(self):
        conn, addr = self.testbed_control_socket.accept()
        self.logger.info("testbed_control")
        while(True):
            size_msg = conn.recv(struct.calcsize("i"))
            if (len(size_msg) <= 0):
                conn.close()
                self.testbed_control_socket.close()
                return
            size = struct.unpack("i", size_msg)[0]
            msg = conn.recv(size)
            msg = msg.decode()
            selection,data = msg.split("_")
            if (selection == "topology"):
                f = open(data, "r")
                self.topology = _byteify(json.load(f, object_hook=_byteify))["ryu_topology"]
                f.close()
                self.reset_network()
            elif (selection == "link"):
                action,timeout,ifaces = data.split("-")
                nodeA,nodeB = ifaces.split("/")
                nodeA,nodeB = int(nodeA), int(nodeB)
                self.logger.info("%s, %s, %s, %s, %s"%(selection, action, timeout, nodeA, nodeB))
                nodeA_switch_id, nodeA_port = self.topology[nodeA][nodeB].split(":")
                nodeB_switch_id, nodeB_port = self.topology[nodeB][nodeA].split(":")
                datapath = self.datapath[self.testbed_datapath[nodeA_switch_id]]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                if action == "down":
                    sleep(float(timeout))
                    match = parser.OFPMatch(in_port=int(nodeA_port))
                    self.remove_flow(datapath=datapath, table_id=0, priority=1, match=match)
                    match = parser.OFPMatch(in_port=int(nodeB_port))
                    self.remove_flow(datapath=datapath, table_id=0, priority=1, match=match)
                elif action == "up":
                    match = parser.OFPMatch(in_port=int(nodeA_port))
                    actions = [parser.OFPActionOutput(int(nodeB_port))]
                    instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
                    self.insert_flow(datapath=datapath, table_id=0, priority=1, match=match, instructions=instructions)
                    match = parser.OFPMatch(in_port=int(nodeB_port))
                    actions = [parser.OFPActionOutput(int(nodeA_port))]
                    instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
                    self.insert_flow(datapath=datapath, table_id=0, priority=1, match=match, instructions=instructions)
            elif (selection == "reset"):
                self.reset_network()
        return
    
    def flow_control(self):
        datapath = self.datapath["0x1"]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        conn, addr = self.flow_control_socket.accept()
        self.logger.info("flow_control")
        while(True):
            size_msg = conn.recv(struct.calcsize("i"))
            if (len(size_msg) <= 0):
                conn.close()
                self.flow_control_socket.close()
                return
            size = struct.unpack("i", size_msg)[0]
            msg = conn.recv(size)
            msg = msg.decode()
            selection,data = msg.split("_")
            if (selection == "cf"):
                command,switch_ip,control_ip,output=data.split("-")
                self.logger.info("%s, %s, %s, %s, %s"%(selection, command, switch_ip, control_ip, output))
                if (command == "add"):
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=control_ip, ipv4_dst=switch_ip)
                    actions = [parser.OFPActionOutput(int(output))]
                    instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
                    self.insert_flow(datapath=datapath, table_id=0, priority=2, match=match, instructions=instructions)
                    match = parser.OFPMatch(eth_type=0x0806, arp_spa=control_ip, arp_tpa=switch_ip)
                    actions = [parser.OFPActionOutput(int(output))]
                    instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
                    self.insert_flow(datapath=datapath, table_id=0, priority=2, match=match, instructions=instructions)
                elif (command == "del"):
                    match = parser.OFPMatch(eth_type=0x0806, arp_spa=control_ip, arp_tpa=switch_ip)
                    self.remove_flow(datapath=datapath, table_id=0, priority=2, match=match)
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=switch_ip, ipv4_dst=switch_ip)
                    self.remove_flow(datapath=datapath, table_id=0, priority=2, match=match)
        return 
    
    def reset_network(self):
        for did in self.testbed_datapath:
            datapath = self.datapath[self.testbed_datapath[did]]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            self.delete_all_flow(datapath=datapath, table_id=1, priority=1)
        self.mapping_links = []
        
        for i in self.topology:
            for j in self.topology[i]:
                i_switch_id, i_port = self.topology[i][j].split(":")
                j_switch_id, j_port = self.topology[j][i].split(":")
                self.mapping_links.append((i,j))
                datapath = self.datapath[self.testbed_datapath[i_switch_id]]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                match = parser.OFPMatch(in_port=int(i_port))
                actions = [parser.OFPActionOutput(int(j_port))]
                instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
                self.insert_flow(datapath=datapath, table_id=0, priority=1, match=match, instructions=instructions)
                datapath = self.datapath[self.testbed_datapath[j_switch_id]]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                match = parser.OFPMatch(in_port=int(j_port))
                actions = [parser.OFPActionOutput(int(i_port))]
                instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
                self.insert_flow(datapath=datapath, table_id=0, priority=1, match=match, instructions=instructions)
        
        self.logger.info("%s"%str(self.mapping_links))
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.logger.info("Switch ID: %s join"%(hex(datapath.id)))
        self.datapath.setdefault(hex(datapath.id), datapath)
        if (len(self.datapath) == 3):
            self._threads.append(hub.spawn(self.testbed_control))
            self._threads.append(hub.spawn(self.flow_control))
        
    def insert_flow(self, datapath, table_id, priority, match, instructions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=table_id, match=match, instructions=instructions)
        datapath.send_msg(mod)
    
    def remove_flow(self, datapath, table_id, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        cookie = cookie_mask = idle_timeout = hard_timeout = 0
        buffer_id = ofproto.OFP_NO_BUFFER
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
        mod = parser.OFPFlowMod(datapath, cookie, cookie_mask, table_id, ofproto.OFPFC_DELETE, idle_timeout, hard_timeout, priority, buffer_id, ofproto.OFPP_ANY, ofproto.OFPG_ANY, ofproto.OFPFF_SEND_FLOW_REM, match, instructions)
        datapath.send_msg(mod)
    
    def delete_all_flow(self, datapath, table_id, priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        cookie = cookie_mask = idle_timeout = hard_timeout = 0
        buffer_id = ofproto.OFP_NO_BUFFER
        match = parser.OFPMatch()
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
        mod = parser.OFPFlowMod(datapath, cookie, cookie_mask, table_id, ofproto.OFPFC_DELETE, idle_timeout, hard_timeout, priority, buffer_id, ofproto.OFPP_ANY, ofproto.OFPG_ANY, ofproto.OFPFF_SEND_FLOW_REM, match, instructions)
        datapath.send_msg(mod)
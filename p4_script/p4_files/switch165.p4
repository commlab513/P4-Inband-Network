# include <core.p4>
# include <v1model.p4>

# include "include/header.p4"
# include "include/parser.p4"
# include "swinfo/sw165info.p4"

const bit<9>    GRPC_PORT   = 9w254;
const bit<9>    CPU_PORT    = 9w255;
const ip4Addr_t MULTICAST_IP   = 32w3758096584;
const macAddr_t MULTICAST_MAC   = 48w1101088686280;

control MyVerifyChecksum(inout headers hdr, inout metadata_t metadata) { apply {  } }

control MyIngress(inout headers hdr,inout metadata_t metadata,inout standard_metadata_t standard_metadata) { 
    register<bit<1>>(1)     initialization; 
    register<bit<16>>(1)    control_port; 
    register<bit<48>>(1)    switch_discovery_timestamp; 
    
    // Data traffic
    action drop () { 
        mark_to_drop(standard_metadata); 
    }
    action set_output (bit<3> priority, PortID_t port) { 
        standard_metadata.priority=priority;
        standard_metadata.egress_spec = port; 
    }
    table ipv4_forwarding {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            metadata.forwarding_message_type: exact;
        }
        actions = {
            NoAction;
            set_output;
        }
        default_action = NoAction();
        size = 16384;
    }
    table arp_forwarding {
        key = {
            hdr.arp_rarp_ipv4.srcProtoAddr: exact;
            hdr.arp_rarp_ipv4.dstProtoAddr: exact;
        }
        actions = {
            NoAction;
            set_output;
        }
        default_action = NoAction();
        size = 16384;
    }

    //P4 In-band Network Messages
    action S2C_message () { 
        ip4Addr_t temp_ipv4 = hdr.ipv4.srcAddr;
        hdr.ipv4.dstAddr = temp_ipv4;
        hdr.ipv4.srcAddr = switch_ip;
        hdr.S2C_message_packet_in_header.setValid();
        hdr.S2C_message_packet_in_header.sender_switch_id = device_id;
        hdr.S2C_message_packet_in_header.sender_port_id = (bit<16>)standard_metadata.ingress_port;
        hdr.S2C_message_packet_in_header.inner_type = hdr.P4_inband_control_header.type;
        hdr.S2C_message_packet_in_header.inner_mtype = hdr.P4_inband_control_header.mtype;
        hdr.P4_inband_control_header.type = 8w2;
        hdr.P4_inband_control_header.mtype = 8w1;
        standard_metadata.priority=3w1;
        standard_metadata.egress_spec = (bit<9>) metadata.control_port; 
    }

    // C2S
    action C2S_forwarding_packet (bit<16> port_id) {
        hdr.ipv4.dstAddr = MULTICAST_IP;
        hdr.P4_inband_control_header.type = hdr.C2S_message_packet_out_header.inner_type; 
        hdr.P4_inband_control_header.mtype = hdr.C2S_message_packet_out_header.inner_mtype;
        hdr.C2S_message_packet_out_header.setInvalid();
        standard_metadata.priority=3w1;
        standard_metadata.egress_spec = (PortID_t) port_id; 
    }
    action C2S_multicast_packet (bit<16> port_id) { 
        hdr.ipv4.dstAddr = MULTICAST_IP;
        hdr.P4_inband_control_header.type = hdr.C2S_message_packet_out_header.inner_type; 
        hdr.P4_inband_control_header.mtype = hdr.C2S_message_packet_out_header.inner_mtype;
        hdr.C2S_message_packet_out_header.setInvalid();
        standard_metadata.priority=3w1;
        standard_metadata.mcast_grp = port_id;
    }

    action switch_alive_reply () {
        ip4Addr_t temp_ipv4 = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = temp_ipv4;
        macAddr_t temp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = temp_mac;
        hdr.P4_inband_control_header.type = 8w2;
        standard_metadata.priority=3w1;
        standard_metadata.egress_spec = standard_metadata.ingress_port; 
    }
    action check_state_reply () {
        ip4Addr_t temp_ipv4 = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = temp_ipv4;
        macAddr_t temp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = temp_mac;
        hdr.P4_inband_control_header.type = 8w2;
        standard_metadata.priority=3w1;
        standard_metadata.egress_spec = standard_metadata.ingress_port; 
    }
    
    // Configuration update message
    table cu_switch_port {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            NoAction;
            drop;
        }
        default_action = drop();
        size = 16384;
    }
    action configuration_update_reply (){
        initialization.write(0, 1w1);
        control_port.write(0, hdr.configuration_update_message_header.update_switch_port_id);
        hdr.P4_inband_control_header.mtype = hdr.P4_inband_control_header.mtype + 8w1;
        hdr.configuration_update_message_header.setInvalid();
        hdr.configuration_success_message_header.setValid();
        hdr.configuration_success_message_header.update_switch_id = device_id;
        standard_metadata.priority=3w1;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        
    }

    // Switch discovery message
    action switch_discovery_message_reply (){
        hdr.switch_discovery_message_header.setInvalid();
        hdr.switch_registration_message_header.setValid();
        hdr.P4_inband_control_header.mtype = hdr.P4_inband_control_header.mtype + 8w1;
        hdr.switch_registration_message_header.switch_id = device_id;
        hdr.switch_registration_message_header.auth_code = authentication_code;
        hdr.switch_registration_message_header.swithc_port_id = (bit<16>) standard_metadata.ingress_port;
        standard_metadata.priority=3w1;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    table sr_switch_port {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            NoAction;
            drop;
        }
        default_action = NoAction();
        size = 16384;
    }
    
    // Topology discovery message
    action network_monitoring_message_reply () {
        hdr.link_state_update_message_header.setValid();
        hdr.P4_inband_control_header.mtype = hdr.P4_inband_control_header.mtype + 8w1;
        hdr.link_state_update_message_header.sender_switch_id = hdr.network_monitoring_message_header.sender_switch_id;
        hdr.link_state_update_message_header.target_switch_id = device_id; 
        hdr.link_state_update_message_header.target_port_id = (bit<16>)standard_metadata.ingress_port;
        hdr.network_monitoring_message_header.setInvalid();
        standard_metadata.priority=3w1;
        standard_metadata.egress_spec = standard_metadata.ingress_port; 
    }

    apply { 
        control_port.read(metadata.control_port, 0);
        if (hdr.ipv4.isValid()) { 
            if (ipv4_forwarding.apply().miss){
                if (! hdr.P4_inband_control_header.isValid()) {
                    if (standard_metadata.ingress_port == GRPC_PORT) {
                        set_output(3w1, (bit<9>)metadata.control_port);
                    } else if (standard_metadata.ingress_port == (bit<9>)metadata.control_port && hdr.ipv4.dstAddr == switch_ip) {
                        set_output(3w1, GRPC_PORT);
                    } 
                } else {
                    if (hdr.network_monitoring_message_header.isValid()) {
                        network_monitoring_message_reply();
                    } else if (hdr.switch_alive_message_header.isValid()) {
                        if (hdr.switch_alive_message_header.switch_id == device_id) {
                            switch_alive_reply();
                        }
                    } else if (hdr.check_state_message_header.isValid()) {
                        if (hdr.check_state_message_header.switch_id == device_id) {
                            check_state_reply();
                        }
                    } else if (hdr.C2S_message_packet_out_header.isValid()) {
                        if (hdr.C2S_message_packet_out_header.target_switch_id == device_id) {
                            switch_discovery_timestamp.write(0,standard_metadata.ingress_global_timestamp);
                            bit<16> port_id = hdr.C2S_message_packet_out_header.target_port_id;
                            if (port_id<200 || port_id==250 || port_id==254){
                                C2S_forwarding_packet(port_id);
                            } else {
                                C2S_multicast_packet(port_id);
                            }
                        }
                    } else if (hdr.configuration_update_message_header.isValid()) {
                        initialization.read(metadata.initialization, 0); // For the first connection
                        if (cu_switch_port.apply().hit || metadata.initialization == 1w0){
                            if (hdr.configuration_update_message_header.update_switch_id == device_id) {
                                configuration_update_reply();
                            }
                        }
                    } else if (hdr.switch_discovery_message_header.isValid()) {
                        sr_switch_port.apply();
                        switch_discovery_timestamp.read(metadata.switch_discovery_timestamp, 0);
                        if (standard_metadata.ingress_global_timestamp - metadata.switch_discovery_timestamp > 48w10000000) {
                            switch_discovery_message_reply();
                        } 
                    } else {
                        S2C_message();
                    }
                } 
            }
        } else if (hdr.arp_rarp_ipv4.isValid()) { 
            if (standard_metadata.ingress_port == GRPC_PORT) {
                set_output(3w1, (bit<9>)metadata.control_port);
            } else if (standard_metadata.ingress_port == (bit<9>)metadata.control_port && hdr.arp_rarp_ipv4.dstProtoAddr == switch_ip) {
                set_output(3w1, GRPC_PORT);
            } else {
                arp_forwarding.apply(); 
            }
        }
    }
} 

control MyEgress(inout headers hdr,inout metadata_t metadata,inout standard_metadata_t standard_metadata) { 
    apply { 
 
    } 
}

control MyComputeChecksum(inout headers  hdr, inout metadata_t metadata) { 
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.dscp,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

V1Switch( MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser() ) main;
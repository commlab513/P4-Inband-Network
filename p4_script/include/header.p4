/* -*- P4_16 -*- */
# include <core.p4>
# include <v1model.p4>

typedef bit<48>  macAddr_t;
typedef bit<32>  ip4Addr_t;
typedef bit<9>   PortID_t;
typedef bit<32>  SessionID_t;

header ethernet_t {
    macAddr_t   dstAddr;
    macAddr_t   srcAddr;
    bit<16>     etherType;
}

header arp_rarp_t {
    bit<16>     hwtype;
    bit<16>     protoType;
    bit<8>      hwAddrLen;
    bit<8>      protoAddrLen;
    bit<16>     opcode;
}

header arp_rarp_ipv4_t {
    macAddr_t   srcHwAddr;
    ip4Addr_t   srcProtoAddr;
    macAddr_t   dstHwAddr;
    ip4Addr_t   dstProtoAddr;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      dscp;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    ip4Addr_t   srcAddr;
    ip4Addr_t   dstAddr;
}

header udp_t {
    bit<16>     srcPort;
    bit<16>     dstPort;
    bit<16>     length;
    bit<16>     checksum;
}

header tcp_t {
    bit<16>     srcPort;
    bit<16>     dstPort;
    bit<32>     seqNo;
    bit<32>     ackNo;
    bit<4>      dataOffset;
    bit<4>      res;
    bit<8>      flags;
    bit<16>     window;
    bit<16>     checksum;
    bit<16>     urgentPtr;
}

// P4-In-Band-Network-Headers
header P4IBN_message_header_t {
    bit<8>  type;
}

header switch_alive_query_message_header_t {
    bit<16> target_switch_id;
}
header switch_alive_response_message_header_t {
    bit<16> response_switch_id;
}

header switch_discovery_message_header_t { 
    bit<16> transit_switch_id;
    bit<16> transit_switch_port_id;
}
header switch_registration_message_header_t {
    bit<16> transit_switch_id;
    bit<16> transit_switch_port_id;
    bit<16> response_switch_id;
    bit<16> response_swithc_port_id;
    bit<48> switch_authentication_code;    
}

header network_monitoring_message_header_t {
    bit<16> transit_switch_id;
    bit<16> transit_switch_port_id;
}
header link_state_update_message_header_t {
    bit<16> transit_switch_id;
    bit<16> transit_switch_port_id;
    bit<16> response_switch_id;
    bit<16> response_switch_port_id;
}

header configuration_update_message_header_t {
    bit<16> target_switch_id;
    bit<16> control_switch_port_id;
}
header configuration_success_message_header_t {
    bit<16> response_switch_id;
    bit<16> control_switch_port_id;
}

header broadcast_sd_nm_message_header_t { }

header inner_port_header_t {
    bit<16> transit_switch_id;
    bit<16> transit_switch_port_id;
}

header  send_payload_to_port_message_header_t {
    bit<16> forwarding_port_id;
}

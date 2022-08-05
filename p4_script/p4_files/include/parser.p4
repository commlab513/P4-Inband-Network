/* -*- P4_16 -*- */
/*  Implementing RTT Module @ P4
 *  Clone Packet
 *  V1Model Updata?
*/

# include <core.p4>
# include <v1model.p4>

const   bit<16>   ETHERNET_TYPE_ARP     =   16w0x0806;
const   bit<16>   ETHERNET_TYPE_IPV4    =   16w0x0800;

const   bit<8>  IP_PROTOCOL_TCP =   8w0x6;
const   bit<8>  IP_PROTOCOL_UDP =   8w0x11;
const   bit<8>  IP_PROTOCOL_P4IBN =   8w0xFE;
const   bit<64>   GRPC_PREAMBLE   =   64w0x1122334455667788;

/* Header*/
struct metadata_t { 
    bit<1> initialization;
    bit<16> control_port;
    bit<16> l4_packet_length;
    bit<48> switch_discovery_timestamp;
    bit<1> switch_discovery_flag;
    bit<1> forwarding_message_type;

}

struct headers {
    packet_in_header_t              packet_in_header;
    packet_out_header_t             packet_out_header;
    ethernet_t ethernet;
    arp_rarp_t arp_rarp;
    arp_rarp_ipv4_t arp_rarp_ipv4;
    ipv4_t ipv4;
    P4_inband_control_header_t P4_inband_control_header;
    C2S_message_packet_out_header_t  C2S_message_packet_out_header;
    S2C_message_packet_in_header_t  S2C_message_packet_in_header;
    switch_alive_message_header_t  switch_alive_message_header;
    check_state_message_header_t check_state_message_header;
    switch_discovery_message_header_t switch_discovery_message_header; 
    network_monitoring_message_header_t network_monitoring_message_header; 
    configuration_update_message_header_t configuration_update_message_header; 
    switch_registration_message_header_t switch_registration_message_header; 
    link_state_update_message_header_t link_state_update_message_header; 
    configuration_success_message_header_t configuration_success_message_header; 
    tcp_t tcp;
    udp_t udp;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata_t metadata, inout standard_metadata_t standard_metadata) {
    state start {
        metadata.forwarding_message_type = 1w0;
        transition select(packet.lookahead<bit<64>>()) {
            GRPC_PREAMBLE:  parse_packet_out_header;
            default: parse_ethernet;
        }
    }
    state parse_packet_out_header {
        packet.extract(hdr.packet_out_header);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERNET_TYPE_ARP:  parse_arp_rarp;
            ETHERNET_TYPE_IPV4: parse_ipv4;
            default:            accept;
        }
    }
    
    state parse_arp_rarp {
        packet.extract(hdr.arp_rarp);
        transition select(hdr.arp_rarp.protoType) {
            ETHERNET_TYPE_IPV4:  arp_rarp_ipv4;
            default:    accept;
        }
    }
    state arp_rarp_ipv4 {
        packet.extract(hdr.arp_rarp_ipv4);
        transition accept;
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        metadata.l4_packet_length = hdr.ipv4.totalLen-16w20;
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOL_TCP:    parse_tcp;
            IP_PROTOCOL_UDP:    parse_udp;
            IP_PROTOCOL_P4IBN:  parse_P4_inband_control_header;
            default:    accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_P4_inband_control_header {
        packet.extract(hdr.P4_inband_control_header);
        transition select(hdr.P4_inband_control_header.type) {
            8w1:  parse_C2S_message_header;
            8w2:  parse_S2C_message_header;
            8w3:  parse_S2S_message_header;
            default:    accept;
        }
    }

    state parse_C2S_message_header {
        transition select(hdr.P4_inband_control_header.mtype) {
            8w1:  parser_packet_out_header;
            8w2:  parser_switch_alive_message_header;
            8w3:  parser_check_state_message_header;
            default:    accept;
        }
    }
    state parse_S2C_message_header {
        transition select(hdr.P4_inband_control_header.mtype) {
            8w1:  parser_packet_in_header;
            8w2:  parser_switch_alive_message_header;
            8w3:  parser_check_state_message_header;
            default:    accept;
        }
    }
    state parser_packet_out_header {
        packet.extract(hdr.C2S_message_packet_out_header);
        transition accept;
    }
    state parser_packet_in_header {
        packet.extract(hdr.S2C_message_packet_in_header);
        transition accept;
    }
    state parser_switch_alive_message_header {
        packet.extract(hdr.switch_alive_message_header);
        metadata.forwarding_message_type = 1w1;
        transition accept;
    }
    state parser_check_state_message_header {
        packet.extract(hdr.check_state_message_header);
        transition accept;
    }

    state parse_S2S_message_header {
        transition select(hdr.P4_inband_control_header.mtype) {
            8w1:  parse_switch_discovery_message_header;
            8w2:  parse_switch_registration_message_header;
            8w3:  parse_network_monitoring_message_header;
            8w4:  parse_link_state_update_message_header;
            8w5:  parse_configuration_update_message_header;
            8w6:  parse_configuration_success_message_header;
            default:    accept;
        }
    }

    state parse_switch_discovery_message_header {
        packet.extract(hdr.switch_discovery_message_header);
        transition accept;
    }
    state parse_switch_registration_message_header {
        packet.extract(hdr.switch_registration_message_header);
        transition accept;
    }
    state parse_network_monitoring_message_header {
        packet.extract(hdr.network_monitoring_message_header);
        transition accept;
    }    
    state parse_link_state_update_message_header {
        packet.extract(hdr.link_state_update_message_header);
        transition accept;
    }
    state parse_configuration_update_message_header {
        packet.extract(hdr.configuration_update_message_header);
        transition accept;
    }
    state parse_configuration_success_message_header {
        packet.extract(hdr.configuration_success_message_header);
        transition accept;
    }    
}

control MyDeparser(packet_out packet, in headers hdr) { 
    apply {
        packet.emit(hdr.packet_out_header);
        packet.emit(hdr.packet_in_header);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp_rarp);
        packet.emit(hdr.arp_rarp_ipv4);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.P4_inband_control_header);
        packet.emit(hdr.C2S_message_packet_out_header);
        packet.emit(hdr.S2C_message_packet_in_header);
        packet.emit(hdr.switch_alive_message_header);
        packet.emit(hdr.check_state_message_header);
        packet.emit(hdr.switch_discovery_message_header);
        packet.emit(hdr.network_monitoring_message_header);
        packet.emit(hdr.configuration_update_message_header);
        packet.emit(hdr.switch_registration_message_header);
        packet.emit(hdr.link_state_update_message_header);
        packet.emit(hdr.configuration_success_message_header);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        
    }
} 
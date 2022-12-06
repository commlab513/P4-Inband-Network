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
const   bit<8>  IP_PROTOCOL_P4IBN = 8w0xFE;

/* Header*/
struct metadata_t { 
    bit<1> initialization;
    bit<16> control_port;
    bit<16> l4_packet_length;
    bit<48> switch_discovery_timestamp;
    bit<1> switch_discovery_flag;
    bit<1> forwarding_message_type;
    bit<1> inner_message;
}

struct headers {
    ethernet_t ethernet;
    arp_rarp_t arp_rarp;
    arp_rarp_ipv4_t arp_rarp_ipv4;
    ipv4_t ipv4;
    
    // Types of P4 IBN 
    P4IBN_message_header_t P4IBN_message_header;    
    
    // Switch discovery and registration
    switch_discovery_message_header_t switch_discovery_message_header; 
    switch_registration_message_header_t switch_registration_message_header; 
    
    // Network monitoring 
    network_monitoring_message_header_t network_monitoring_message_header; 
    link_state_update_message_header_t link_state_update_message_header; 
    
    // Configuration update
    configuration_success_message_header_t configuration_success_message_header; 
    configuration_update_message_header_t configuration_update_message_header; 
    
    // Switch alive detection
    switch_alive_query_message_header_t  switch_alive_message_header;
    switch_alive_response_message_header_t switch_alive_response_message_header;
    
    // Send payload to port 
    send_payload_to_port_message_header_t  send_payload_to_port_message_header;

    // broadcast SD/NM message
    broadcast_sd_nm_message_header_t broadcast_sd_nm_message_header;
    P4IBN_message_header_t inner_P4IBN_message_header;    
    inner_port_header_t inner_port_header;
 
    // P4Runtime API/ UDP requirement header
    tcp_t tcp;
    udp_t udp;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata_t metadata, inout standard_metadata_t standard_metadata) {
    state start {
        metadata.forwarding_message_type = 1w0;
        metadata.inner_message = 1w0;
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

    state parse_P4IBN_message_header {
        packet.extract(hdr.P4IBN_message_header);
        transition select(hdr.P4IBN_message_header.type) {
            8w1:  parse_sd_message_header; 
            8w2:  parse_sr_message_header; 
            8w3:  parse_nm_message_header; 
            8w4:  parse_lsu_message_header; 
            8w5:  parse_cu_message_header; 
            8w6:  parse_cs_message_header; 
            8w7:  parse_saq_message_header; 
            8w8:  parse_sar_message_header; 
            8w9:  parse_BSDNM_message_header; 
            8w10: parse_SP2P_header_header; 
            default:    accept;
        }
    }

    state parse_sd_message_header {
        packet.extract(hdr.switch_discovery_message_header);
        transition accept;
    }
    state parse_sr_message_header {
        packet.extract(hdr.switch_registration_message_header);
        transition accept;
    }
    state parse_nm_message_header {
        packet.extract(hdr.network_monitoring_message_header);
        transition accept;
    }    
    state parse_lsu_message_header {
        packet.extract(hdr.link_state_update_message_header);
        transition accept;
    }
    state parse_cu_message_header {
        packet.extract(hdr.configuration_update_message_header);
        transition accept;
    }
    state parse_cs_message_header {
        packet.extract(hdr.configuration_success_message_header);
        transition accept;
    }    
    state parser_saq_message_header {
        metadata.forwarding_message_type = 1w1;
        packet.extract(hdr.switch_alive_query_message_header);
        transition accept;
    }
    state parser_sar_state_message_header {
        metadata.forwarding_message_type = 1w1;
        packet.extract(hdr.switch_alive_response_message_header);
        transition accept;
    }
    state parser_BSDNM_message_header {
        packet.extract(hdr.broadcast_sd_nm_message_header);
        transition parse_inner_P4IBN_header;
    }
    state parse_inner_P4IBN_header {
        metadata.inner_message = 1w1;
        packet.extract(hdr.inner_P4IBN_message_header);
        packet.extract(hdr.inner_port_header)
        transition accept;
    }
    state parser_SP2P_message_header {
        packet.extract(hdr.send_payload_to_port_message_header);
        transition accept;
    }
}

control MyDeparser(packet_out packet, in headers hdr) { 
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp_rarp);
        packet.emit(hdr.arp_rarp_ipv4);
        packet.emit(hdr.ipv4);
        // P4 Inband message headder
        packet.emit(hdr.P4IBN_message_header);
        // Switch discovvery
        packet.emit(hdr.switch_discovery_message_header);
        packet.emit(hdr.switch_registration_message_header);
        // Network monitoring message
        packet.emit(hdr.network_monitoring_message_header);
        packet.emit(hdr.link_state_update_message_header);
        // configuration update
        packet.emit(hdr.configuration_update_message_header);
        packet.emit(hdr.configuration_success_message_header);
        // Switch alive detection
        packet.emit(hdr.switch_alive_message_query_header);
        packet.emit(hdr.switch_alive_message_response_header);
        // send payload to port
        packet.emit(hdr.send_payload_to_port_message_header);
        // Broadcast SD/NM message
        packet.emit(hdr.broadcast_sd_nm_message_header);
        packet.emit(hdr.inner_P4IBN_message_header);
        packet.emit(hdr.inner_port_header);
        // P4Runtime API/ UDP requirement header
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
} 
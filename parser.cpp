#include "parser.h"
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sstream>
#include <iomanip>
#include <netinet/ip.h>
#include "data.h"
#include <netinet/tcp.h>
#include <netinet/udp.h>
parser::parser(packet &x) : p(x){
}

string parser::format_mac_from_unsigned_char_array(unsigned char convert[]){
    stringstream ss;
    for(int i=0; i <6; ++i){
        ss << hex << setw(2) << setfill('0') << (int)convert[i];
        if(i<5){
            ss << ":";
        }
    }
    return ss.str();
}
Eth_Header parser::extract_ethernet_header(){
    // throws template on top of buffer for getting mac dest source and packet type
    Eth_Header extracted;
    struct ethhdr * eth = (struct ethhdr*)(p.getbuffer());
    extracted.source_eth = format_mac_from_unsigned_char_array(eth->h_source);
    extracted.dest_eth = format_mac_from_unsigned_char_array(eth->h_dest);
    extracted.protocol = (int)ntohs(eth->h_proto);

    return extracted;

    
}

struct iphdr* parser::get_ip_header(){
    return (struct iphdr*)(p.getbuffer()+sizeof(struct ethhdr));
}

IP_Header parser::extract_ip_header(){
    IP_Header extraction;
    unsigned short hdr_len = 0;
    struct iphdr* ip = get_ip_header();
    // create zeroed out memory for ips the dest and source ips
    sockaddr_in source{};
    sockaddr_in dest{};

    // fill in the source address and destination address now
    source.sin_addr.s_addr = ip->saddr;
    dest.sin_addr.s_addr = ip->daddr;


    extraction.source_IP = string(inet_ntoa(source.sin_addr));
    extraction.dest_IP = string(inet_ntoa(dest.sin_addr));
    extraction.protocol = ip->protocol;
    

    return extraction;


}

TCP_Header parser::extract_TCP_Header(){
    TCP_Header extraction;
    struct tcphdr *tcp = (struct tcphdr*)(p.getbuffer() + get_transport_offset());
    extraction.source_port = ntohs(tcp->source);
    extraction.destination_port = ntohs(tcp->dest);
    extraction.sequence_num = ntohl(tcp->seq);
    extraction.data_offset = (tcp->th_off);
    extraction.ack_num = ntohl(tcp->ack_seq);
    extraction.flags = (tcp->th_flags);
    extraction.header_len = extraction.data_offset * 4;

    return extraction;
}

int parser::get_transport_offset(){
    struct iphdr* ip = get_ip_header();
    return ip->ihl *4 + sizeof(struct ethhdr);
}


UDP_Header parser::extract_UDP_Header(){
    struct udphdr* udp = (struct udphdr*)(p.getbuffer()+get_transport_offset());

    UDP_Header extraction;
    extraction.destination_port = ntohs(udp->dest);
    extraction.source_port = ntohs(udp->source);
    extraction.len = ntohs(udp->len);
    extraction.checksum = ntohs(udp->check);


    return extraction;
}


int parser::identify_protocol(){
    struct iphdr* ip = get_ip_header();
    return ip->protocol; // 6 = TCP, 17 = UDP, 1 = ICMP, etc.
}

Data parser::get_data_start(){
    Data extraction;
    int transport_header_len = 0;

    int proto = identify_protocol(); // single check, instead of re-deriving it here AND in main
    if(proto == 6){ // TCP
        struct tcphdr* tcp = (struct tcphdr*)(p.getbuffer() + get_transport_offset());
        transport_header_len = tcp->th_off * 4;
    }
    else if(proto == 17){ // UDP
        transport_header_len = sizeof(struct udphdr);
    }
    // else: unknown transport (e.g. ICMP has no ports/transport header the same way),
    // transport_header_len stays 0, payload starts right after the IP header

    extraction.start_of_data = p.getbuffer() + get_transport_offset() + transport_header_len;
    extraction.num_bytes = p.getsize() - (get_transport_offset() + transport_header_len);

    return extraction;
}
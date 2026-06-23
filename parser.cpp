#include "parser.h"
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sstream>
#include <iomanip>
#include <netinet/ip.h>
#include "data.h"
parser::parser(packet x){
    p = x;
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

IP_Header parser::extract_ip_header(){
    IP_Header extraction;
    unsigned short hdr_len = 0;
    struct iphdr* ip = (struct iphdr*)(p.getbuffer()+sizeof(struct ethhdr));
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


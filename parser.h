#ifndef PARSER_H
#define PARSER_H

#include "packet.h"
#include "data.h"
#include <string>

struct iphdr; // forward declare so we don't need netinet/ip.h in the header

class parser{

private:
    packet& p;
    std::string source_eth;
    std::string dest_eth;
    std::string source_IP;
    std::string dest_IP;
    std::string protocol;

    std::string format_mac_from_unsigned_char_array(unsigned char[]);
    struct iphdr* get_ip_header(); 


public:
    parser(packet&);
    Eth_Header extract_ethernet_header();
    IP_Header extract_ip_header();
    /* this offset is in bytes*/ 

    TCP_Header extract_TCP_Header();
    int get_transport_offset();
    UDP_Header extract_UDP_Header();
    int identify_protocol(); 
    Data get_data_start();
    Parsed_Packet parse_all();
    ICMP_Header extract_ICMP_Header();
};

#endif
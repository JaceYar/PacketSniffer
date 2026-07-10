#ifndef PARSER_H
#define PARSER_H

#include "packet.h"
#include "data.h"

struct iphdr; // forward declare so we don't need netinet/ip.h in the header

using namespace std;

class parser{

private:
    packet& p;
    string source_eth;
    string dest_eth;
    string source_IP;
    string dest_IP;
    string protocol;

    string format_mac_from_unsigned_char_array(unsigned char[]);
    struct iphdr* get_ip_header(); // DRY: shared by extract_ip_header, get_transport_offset, get_data_start


public:
    parser(packet&);
    Eth_Header extract_ethernet_header();
    IP_Header extract_ip_header();
    /* this offset is in bytes*/ 

    TCP_Header extract_TCP_Header();
    int get_transport_offset();
    UDP_Header extract_UDP_Header();
    int identify_protocol(); // returns ip->protocol (6=TCP, 17=UDP, etc), single source of truth
    Data get_data_start();
    Parsed_Packet parse_all();
    ICMP_Header extract_ICMP_Header();
};







#endif
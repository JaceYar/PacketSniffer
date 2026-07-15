#ifndef DATA_H
#define DATA_H
#include <iostream>
#include <string>

struct Data{
    unsigned char* start_of_data;
    int num_bytes =0;
};

struct ICMP_Header{
    int type;
    int code;

};

struct TCP_Header{
    int source_port;
    int destination_port;
    unsigned int sequence_num;
    int data_offset;
    unsigned int ack_num;
    int flags;
    int header_len;

};

struct UDP_Header{
    int source_port;
    int destination_port;
    int checksum;
    int len;
};

struct IP_Header{
    std::string source_IP;
    std::string dest_IP;
    int protocol;
    
    int hdr_len;

    std::string protocol_to_string();



};

struct Eth_Header{
    std::string source_eth;
    std::string dest_eth;
    int protocol;

    std::string protocol_to_string();
};

struct Parsed_Packet{
    Eth_Header eth;
    IP_Header Ip;
    UDP_Header UDP;
    TCP_Header TCP;
    Data the_data;
    ICMP_Header icmp;

    bool has_udp = false;
    bool has_tcp = false;
    bool has_ip = false;
    bool ipv4 = false;
    bool is_icmp = false;
};

#endif
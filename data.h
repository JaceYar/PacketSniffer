#ifndef DATA_H
#define DATA_H
#include <iostream>
#include <string>

using namespace std;

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
    int sequence_num;
    int len;
};

struct IP_Header{
    string source_IP;
    string dest_IP;
    int protocol;
    
    int hdr_len;

    string protocol_to_string();



};

struct Eth_Header{
    string source_eth;
    string dest_eth;
    int protocol;

    string protocol_to_string();
};

struct Transport_Layer_Header{


};





#endif
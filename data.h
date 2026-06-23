#ifndef DATA_H
#define DATA_H
#include <iostream>
#include <string>

using namespace std;

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
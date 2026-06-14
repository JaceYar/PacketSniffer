#ifndef PARSER_H
#define PARSER_H

#include "packet.h"
#include "data.h"


using namespace std;

class parser{

private:
    packet p;
    string source_eth;
    string dest_eth;
    string source_IP;
    string dest_IP;
    string protocol;

    string format_mac_from_unsigned_char_array(unsigned char[]);


public:
    parser(packet);
    Eth_Header extract_ethernet_header();
    IP_Header extract_ip_header();


};







#endif

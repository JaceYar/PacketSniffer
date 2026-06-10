#ifndef PARSER_H
#define PARSER_H

#include "packet.h"


using namespace std;

class parser{

private:
    packet p;
    string source_eth;
    string dest_eth;
    string source_IP;
    string dest_IP;
    int protocol;

    string format_mac_from_unsigned_char_array(unsigned char[]);


public:
    parser(packet);
    void extract_ethernet_header();
    void extract_ip_header();



};







#endif

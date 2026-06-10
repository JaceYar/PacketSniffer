#ifndef PARSER_H
#define PARSER_H

#include "packet.h"


using namespace std;

class parser{

private:
    packet p;
    string source;
    string dest;
    string protocol;

    string format_mac_from_unsigned_char_array(unsigned char[]);


public:
    parser(packet);
    void extract_ethernet_header();



};







#endif

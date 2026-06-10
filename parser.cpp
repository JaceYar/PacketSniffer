#include "parser.h"
#include <linux/if_ether.h>
#include <sstream>
#include <iomanip>

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
void parser::extract_ethernet_header(){
    // throws template on top of buffer for getting mac dest source and packet type
    struct ethhdr * eth = (struct ethhdr*)(p.getbuffer());
    source = format_mac_from_unsigned_char_array(eth->h_source);
    dest = format_mac_from_unsigned_char_array(eth->h_dest);
    protocol = (int)eth->h_proto;
}
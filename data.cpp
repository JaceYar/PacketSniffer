#include "data.h"


string Eth_Header::protocol_to_string(){
    string protocol_name;
    switch(protocol){
        case 2048:
            protocol_name = "IPv4";
            break;

        case 34525:
            protocol_name = "IPv6";
            break;

        case 2054:
            protocol_name = "ARP";
            break;

        case 32821:
            protocol_name = "RARP";
            break;

        case 33024:
            protocol_name = "802.1Q";
            break;

        // add some more cases in later


        default:
            protocol_name = "unknown protocol or protocol not detected";
    }

    return protocol_name;
}
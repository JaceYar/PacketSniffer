#include "data.h"
#include <string>


using namespace std;

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

string IP_Header::protocol_to_string(){
    string protocol_name;
    switch(protocol){
        case 1:
            protocol_name = "ICMP";

        break;

        case 2:
            protocol_name = "IGMP";

        break;

        case 4:
            protocol_name = "IP-in-IP";


        break;

        case 6:
            protocol_name = "TCP";

        break;

        case 17: 
            protocol_name = "UDP";

        break;

        case 41:
            protocol_name = "IPv6";


        break;

        case 47:
            protocol_name = "GRE";

        break;

        case 50:
            protocol_name = "ESP";
        break;

        case 51:
            protocol_name = "AH";
        break;

        case 89:
            protocol_name = "OSPF";

        break;


        default:
            protocol_name = "Unable to Identify Protcol";
    }

    return protocol_name;
}
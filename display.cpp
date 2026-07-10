#include "display.h"
#include <cctype>

ostream& operator<<(ostream& os, const Parsed_Packet& pckt){
    if(pckt.ipv4 == true){
        if(pckt.has_ip == true){
            os << "Destination IP: " << pckt.Ip.dest_IP << endl;
            os << "Source IP: " << pckt.Ip.source_IP << endl;
            if(pckt.Ip.protocol == 6){
                os << "Protcol: TCP" << endl;
                os << "Source Port: " << pckt.TCP.source_port << endl;
                os << "Destination Port: " << pckt.TCP.destination_port << endl; 
                // get the data area
                string output_data ="";
                for(int i=0; i< pckt.the_data.num_bytes; ++i ){
                    unsigned char c = *(pckt.the_data.start_of_data+i);
                    if(!isprint(c)){
                        c = '*';
                    }
                    output_data.push_back(c);
                }
                os << "Data: \n" << output_data << endl;
            }
            else if (pckt.Ip.protocol == 17){
                os << "Protocol: UDP\n" << endl;
                os << "Source Port: " << pckt.UDP.source_port << endl;
                os << "Destination Port: " << pckt.UDP.destination_port << endl;
                // i know this violates repeating yourself but will fix later
                string output_data ="";
                for(int i=0; i< pckt.the_data.num_bytes; ++i ){
                    unsigned char c = *(pckt.the_data.start_of_data+i);
                    if(!isprint(c)){
                        c = '*';
                    }
                    output_data.push_back(c);
                }
                os << "Data: \n" << output_data << endl;
            }
            else if(pckt.Ip.protocol ==1){
                os << "Protocol: ICMP\n" << endl;
                string output_data ="";
                os << "ICMP Code: " << pckt.icmp.code << endl;
                os << "ICMP Type:" << pckt.icmp.type << endl;

                for(int i=0; i< pckt.the_data.num_bytes; ++i ){

                    unsigned char c = *(pckt.the_data.start_of_data+i);
                    if(!isprint(c)){
                        c = '*';
                    }
                    output_data.push_back(c);
                }
                os << "Data: \n" << output_data << endl;
  
            }
        }
        else{
            os << "Packet did not have IP header\n";
        }
    }
    else{
        os << "Not IPV4 Packet\n";
    }
    return os;
}
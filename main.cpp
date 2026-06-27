#include <iostream>
#include "packet.h"
#include "raw.h"
#include "parser.h"
#include "data.h"
using namespace std;




int main(){
    string banner = R"(  _____ _   _          _____      _____ _______ 
 / ____| \ | |   /\   / ____|    |_   _|__   __|
| (___ |  \| |  /  \ | |  __ ______| |    | |   
 \___ \| . ` | / /\ \| | |_ |______| |    | |   
 ____) | |\  |/ ____ \ |__| |     _| |_   | |   
|_____/|_| \_/_/    \_\_____|    |_____|  |_|  
)";


    string linebreak = "------------------------";
    cout << banner << linebreak << linebreak <<  endl;
                                              
    // Inside main() after initializing your Raw socket
    string interface;
    cout << "Please Enter Interface: ";
    cin >> interface;
    Raw sniffer(interface); // Replace with your actual interface (e.g., wlan0, enp3s0)
    unsigned char buffer[65536];

    cout << "Sniffer started... Press Ctrl+C to stop." << endl;
    int packet_count = 0;

    while(true) {
        int size = sniffer.capture_packet(buffer, 65536);
        if (size < 0) {
            cout << "Error capturing packet!" << endl;
            break;
        }
        packet p = packet(buffer,size);
        parser chop(p);
        Eth_Header ethernet;
        ethernet = chop.extract_ethernet_header();

        // need to put switch here for future

        if(ethernet.protocol == 2048){
            IP_Header ipHeader;
            ipHeader = chop.extract_ip_header();

            cout << "Destination: " << ipHeader.dest_IP << endl;
            cout << "Source: " << ipHeader.source_IP << endl;

            // if using TCP
            if(ipHeader.protocol == 6){
                TCP_Header tcpHead = chop.extract_TCP_Header();
                cout << "Source Port:" << tcpHead.source_port << endl;
                cout << "Dest Port: " << tcpHead.destination_port << endl;
            }

            // for udp
            else if(ipHeader.protocol == 17){
                // fill in for udp in a bit 
            }

        }
        else{
            cout << "Was not an Ipv4 packet" << endl;
        }

        cout << "Eth Protocol:" << ethernet.protocol_to_string() << endl;
       

        packet_count++;
        cout << "Successfully snagged packet #" << packet_count << " (" << size << " bytes)" << endl;

        cout << endl << endl;
    }




    return 0;
}
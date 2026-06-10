#include <iostream>
#include "packet.h"
#include "raw.h"
#include "parser.h"
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
    Raw sniffer("eth0"); // Replace with your actual interface (e.g., wlan0, enp3s0)
    unsigned char buffer[65536];

    cout << "Sniffer started... Press Ctrl+C to stop." << endl;
    int packet_count = 0;

    while(true) {
        int size = sniffer.capture_packet(buffer, 65536);
        if (size < 0) {
            cout << "Error capturing packet!" << endl;
            break;
        }
        packet_count++;
        cout << "Successfully snagged packet #" << packet_count << " (" << size << " bytes)" << endl;
    }




    return 0;
}
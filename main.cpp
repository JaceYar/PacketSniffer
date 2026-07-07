#include <iostream>
#include "packet.h"
#include "raw.h"
#include "parser.h"
#include "data.h"
#include "display.h"
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

    Raw* sniffer = nullptr;
    try{
        sniffer = new Raw(interface);
    }
    catch (const exception& e){
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
      // Replace with your actual interface (e.g., wlan0, enp3s0)
    unsigned char buffer[65536];

    cout << "Sniffer started... Press Ctrl+C to stop." << endl;
    int packet_count = 0;

    while(true) {
        Parsed_Packet packet_package;
        int size = sniffer->capture_packet(buffer, 65536);
        if (size < 0) {
            cout << "Error capturing packet!" << endl;
            break;
        }
        packet p = packet(buffer,size);
        parser chop(p);
        
        packet_package = chop.parse_all();
        cout << packet_package;

       

        packet_count++;
        cout << "Successfully snagged packet #" << packet_count << " (" << size << " bytes)" << endl;

        cout << endl << endl;
    }


    delete sniffer;

    return 0;
}
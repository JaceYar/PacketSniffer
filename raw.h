#ifndef RAW_H
#define RAW_H

#include <iostream>
#include<sys/socket.h>
#include<netinet/in.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>
#include <net/if.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include<string>
#include<sstream>
#include <iomanip>

using namespace std;

class Raw{
    public:
    //constructor 
    Raw(const string & interface){
        // create the socket
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if(sock < 0){
            // change to throwing an error 
            cout << "failed to make socket" << endl;
        }
        else{
        // init the socket adress on link layer
            sockaddr_ll address;
            // allign address with actual socket
            address.sll_family = AF_PACKET;
            address.sll_protocol = htons(ETH_P_ALL);
            // specify the interface you want to have the socket on 
            address.sll_ifindex= if_nametoindex(interface.c_str());
            // bind the socket t othat interface so it only gets packets on that interface
            bind(sock, (const struct sockaddr*)&address, sizeof(address));
        }
    }
    ~Raw();
    // capture a packet
    int capture_packet(void * buffer, int bufferlen){
        // recvfrom fills the buffer and also returns num of bytes it filled
        // 0 means no flags, NUll,NULL means that we will extract sender stuff ourselves
        return recvfrom(sock, buffer, bufferlen,0,NULL,NULL);
    }

    private:
        int sock;
    
};

#endif 
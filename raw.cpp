#include "raw.h"
#include <unistd.h>

using namespace std;

// constructor implementation
Raw::Raw(const string & interface) {
    // create the socket
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock < 0){
        // change to throwing an error 
        throw runtime_error("Failed to make socket");
    }
    else{
        // init the socket adress on link layer
        sockaddr_ll address{};
        // allign address with actual socket
        address.sll_family = AF_PACKET;
        address.sll_protocol = htons(ETH_P_ALL);

        // specify the interface you want to have the socket on 
        unsigned int idx = if_nametoindex(interface.c_str());
        if(idx == 0){
            throw runtime_error("Interface " + interface + "is not valid");
        }
        else{
            address.sll_ifindex = idx;
        }
        // bind the socket t othat interface so it only gets packets on that interface
        if(bind(sock, (const struct sockaddr*)&address, sizeof(address))<0){
            throw runtime_error("Failed to bind socket to interace");
        };
    }
}

// destructor implementation
Raw::~Raw() {
    // If you need to close the socket when the object dies, it would go here!
    close(sock);
}

// capture a packet implementation
int Raw::capture_packet(void * buffer, int bufferlen) {
    // recvfrom fills the buffer and also returns num of bytes it filled
    // 0 means no flags, NUll,NULL means that we will extract sender stuff ourselves
    return recvfrom(sock, buffer, bufferlen, 0, NULL, NULL);
}
#ifndef RAW_H
#define RAW_H

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string>
#include <sstream>
#include <iomanip>

class Raw {
public:
    //constructor 
    Raw(const std::string & interface);
    
    //destructor
    ~Raw();
    
    // capture a packet
    int capture_packet(void * buffer, int bufferlen);

private:
    int sock;
};

#endif // RAW_H
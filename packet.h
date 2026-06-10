#ifndef PACKET_H
#define PACKET_H
// this is just basically going ot hold the data as far as i am thinking


#include <iostream>

using namespace std;



class packet{
    private:

    unsigned char *buffer;
    unsigned int size;


    public:
    packet();
    packet(unsigned char *buffer, unsigned int);
    unsigned char* getbuffer();


};

#endif
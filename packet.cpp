#include "packet.h"


packet::packet(){

    buffer = new unsigned char[65536];
    size =0;


}
packet::packet(unsigned char* b, unsigned int s){
    buffer =b;
    size =s;
}
unsigned char* packet::getbuffer(){
    return this->buffer;
}
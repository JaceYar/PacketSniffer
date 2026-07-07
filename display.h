#ifndef DISPLAY_H
#define DISPLAY_H


#include <iostream>
#include "parser.h"

using namespace std;


ostream& operator<<(ostream& os, const Parsed_Packet& pckt);



#endif
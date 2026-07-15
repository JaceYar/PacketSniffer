#ifndef DISPLAY_H
#define DISPLAY_H


#include <iostream>
#include "parser.h"

std::ostream& operator<<(std::ostream& os, const Parsed_Packet& pckt);

#endif
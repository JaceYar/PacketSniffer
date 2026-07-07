cmake_minimum_required(VERSION 3.16)
project(PacketSniffer LANGUAGES CXX)

add_executable(sniffer
    main.cpp
    data.cpp
    packet.cpp
    parser.cpp
    raw.cpp
    display.cpp

)

# Test harness -- no main.cpp/raw.cpp needed, since it feeds the
# parser hand-built byte arrays instead of real captured packets.
add_executable(test_parser
    test_parser.cpp
    data.cpp
    packet.cpp
    parser.cpp
    display.cpp
)
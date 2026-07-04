cmake_minimum_required(VERSION 3.16)
project(PacketSniffer LANGUAGES CXX)

add_executable(sniffer
    main.cpp
    data.cpp
    packet.cpp
    parser.cpp
    raw.cpp

)
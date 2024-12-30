cmake_minimum_required(VERSION 3.5)

find_package(Pcap REQUIRED)

set(PROJECT_SOURCES
    parser/packet.cpp
    device.cpp
    parser.cpp
)

add_library(tiny-sniffer-core ${PROJECT_SOURCES})
target_link_libraries(tiny-sniffer-core PUBLIC Pcap::Pcap)

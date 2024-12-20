cmake_minimum_required(VERSION 3.5)

find_package(Pcap REQUIRED)

set(PROJECT_SOURCES
    main.cpp
)

add_executable(tiny-sniffer ${PROJECT_SOURCES})
target_link_libraries(tiny-sniffer PRIVATE Pcap::Pcap)

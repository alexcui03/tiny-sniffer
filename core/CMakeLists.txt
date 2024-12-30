cmake_minimum_required(VERSION 3.5)

find_package(Pcap REQUIRED)

set(PROJECT_SOURCES
    parser/packet.cpp
    device.cpp
    parser.cpp
)

set(PROJECT_HEADERS
    tiny-sniffer.hpp
    parser.hpp
    device.hpp
)

set(PROJECT_HEADERS_PARSER
    parser/packet.hpp
    parser/ethernet.hpp
    parser/ipv4.hpp
    parser/ipv6.hpp
    parser/tcp.hpp
)

add_library(tiny-sniffer-core SHARED ${PROJECT_SOURCES})
target_link_libraries(tiny-sniffer-core PUBLIC Pcap::Pcap)

install(TARGETS tiny-sniffer-core
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES ${PROJECT_HEADERS} DESTINATION include/tiny-sniffer)
install(FILES ${PROJECT_HEADERS_PARSER} DESTINATION include/tiny-sniffer/parser)
install(IMPORTED_RUNTIME_ARTIFACTS)

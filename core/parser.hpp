#pragma once

#include <cstdint>

#include <pcap.h>

class Parser {
public:
    Parser();
    ~Parser();
    void next_package(const void *header, const unsigned char *bytes);
    static int get_datalink_header_length(int datalink_type);
};

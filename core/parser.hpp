#pragma once

#include <cstdint>

#include <pcap.h>

class Parser {
public:
    Parser(int datalink = DLT_EN10MB);
    ~Parser();
    void next_package(const pcap_pkthdr *header, const unsigned char *bytes);
    static int get_datalink_header_length(int datalink_type);
private:
    int datalink_header_length;
};

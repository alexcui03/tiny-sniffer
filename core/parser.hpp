#pragma once

#include <cstdint>
#include <vector>
#include <map>

#include <pcap.h>

#include "parser/packet.hpp"

struct IncompleteIPPacket {
    DatalinkPacket packet;
    std::vector<uint8_t> data;
};

class Parser {
public:
    Parser(int datalink = DLT_EN10MB);
    ~Parser();
    const DatalinkPacket &next_packet(const pcap_pkthdr *header, const unsigned char *bytes, int &additional);
    const DatalinkPacket &assembled_packet(int index);
    static DatalinkProtocol dlt_protocol(int datalink_type);
    static TransportProtocol ip_protocol(int ip_protocol);
    static TransportProtocol ipv6_protocol(int next_header);
private:
    int datalink_type;
    std::vector<DatalinkPacket> packets;
    std::map<uint16_t, IncompleteIPPacket> incomplete_ip_packets;
};

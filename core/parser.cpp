#include "parser.hpp"

#include "parser/ethernet.hpp"
#include "parser/ipv4.hpp"
#include "parser/tcp.hpp"
#include "error.hpp"

#include <iostream>

Parser::Parser(int datalink) {
    this->datalink_header_length = get_datalink_header_length(datalink);
}

Parser::~Parser() {}

void Parser::next_package(const pcap_pkthdr *hdr, const unsigned char *bytes) {
    const u_char *payload = bytes;
    auto ethernet_header = EthernetHeader::parse(payload);
    payload += this->datalink_header_length;

    if (ethernet_header.ethertype == 0x0008) { // IPv4
        auto ip_header = IPv4Header::parse(payload);
        payload += ip_header.header_length();
        switch (ip_header.protocol) {
            case IPPROTO_TCP: {
                auto tcp_header = TCPHeader::parse(payload);
                payload += tcp_header.header_length();
                break;
            }
            default: {
                break;
            }
        }
    } else if (ethernet_header.ethertype == 0xdd86) { // IPv6
        // TODO
    }
}

int Parser::get_datalink_header_length(int datalink_type) {
    switch (datalink_type) {
        case DLT_NULL: return 4;
        case DLT_EN10MB: return 14;
        case DLT_SLIP: [[fallthrough]];
        case DLT_PPP: return 24;
        default: throw pcap_error("unsupported datalink type");
    }
}

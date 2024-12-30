#include "parser.hpp"

#include "error.hpp"

Parser::Parser() {}

Parser::~Parser() {}

void Parser::next_package(const void *header, const unsigned char *bytes) {
    
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

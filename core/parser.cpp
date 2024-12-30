#include "parser.hpp"

#include "parser/ethernet.hpp"
#include "parser/ipv4.hpp"
#include "parser/tcp.hpp"
#include "error.hpp"

Parser::Parser(int datalink): datalink_type(datalink) {}

Parser::~Parser() {}

const DatalinkPacket &Parser::next_packet(const pcap_pkthdr *header, const unsigned char *bytes) {
    const uint8_t *payload = bytes;
    int packet_length = header->len;

    // Parse datalink layer.
    DatalinkPacket &datalink = this->packets.emplace_back();
    NetworkProtocol network_type = NetworkProtocol::INVALID;
    if (this->datalink_type == DLT_EN10MB) { // Ethernet
        auto header = new EthernetHeader(EthernetHeader::parse(payload));
        datalink.protocol = DatalinkProtocol::ETHERNET;
        datalink.header = header;

        // Check payload type.
        switch (header->ethertype) {
            case 0x0008: // IPv4
                network_type = NetworkProtocol::IPV4;
                break;
            case 0xdd86: // IPv6
                network_type = NetworkProtocol::IPV6;
                break;
        }
    } else {
        return datalink;
    }

    // Parse network layer.
    payload += datalink.header->header_length();
    NetworkPacket &network = datalink.payload;
    TransportProtocol transport_type = TransportProtocol::INVALID;
    switch (network_type) {
        case NetworkProtocol::IPV4: {
            auto header = new IPv4Header(IPv4Header::parse(payload));
            network.protocol = NetworkProtocol::IPV4;
            network.header = header;
            transport_type = Parser::ip_protocol(header->protocol);
            break;
        }
        default: {
            return datalink;
        }
    }

    // Parse transport layer.
    payload += network.header->header_length();
    TransportPacket &transport = network.payload;
    switch (transport_type) {
        case TransportProtocol::TCP: {
            auto header = new TCPHeader(TCPHeader::parse(payload));
            transport.protocol = TransportProtocol::TCP;
            transport.header = header;
            break;
        }
        default: {
            return datalink;
        }
    }

    // Parse application layer.
    payload += transport.header->header_length();
    const size_t length = packet_length - (payload - bytes);
    transport.payload.payload = new uint8_t[length];
    transport.payload.length = length;
    std::memcpy(transport.payload.payload, payload, length);

    return datalink;
}

DatalinkProtocol Parser::dlt_protocol(int datalink_type) {
    switch (datalink_type) {
        case DLT_EN10MB: return DatalinkProtocol::ETHERNET;
        default: return DatalinkProtocol::INVALID;
    }
}

TransportProtocol Parser::ip_protocol(int ip_protocol) {
    switch (ip_protocol) {
        case IPPROTO_TCP: return TransportProtocol::TCP;
        default: return TransportProtocol::INVALID;
    }
}

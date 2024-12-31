#include "parser.hpp"

#include "parser/ethernet.hpp"
#include "parser/ipv4.hpp"
#include "parser/ipv6.hpp"
#include "parser/arp.hpp"
#include "parser/icmp.hpp"
#include "parser/icmpv6.hpp"
#include "parser/tcp.hpp"
#include "parser/udp.hpp"
#include "error.hpp"

Parser::Parser(int datalink): datalink_type(datalink) {}

Parser::~Parser() {}

const DatalinkPacket &Parser::assembled_packet(int index) {
    return incomplete_ip_packets[index].packet;
}

const DatalinkPacket &Parser::next_packet(const pcap_pkthdr *header, const unsigned char *bytes, int &additional) {
    const uint8_t *payload = bytes;
    int packet_length = header->len;
    additional = -1; // used by ip reassemble.

    // Parse datalink layer.
    DatalinkPacket &datalink = this->packets.emplace_back();
    NetworkProtocol network_type = NetworkProtocol::INVALID;
    datalink.timestamp = header->ts;
    if (this->datalink_type == DLT_EN10MB) { // Ethernet
        auto header = new EthernetHeader(EthernetHeader::parse(payload));
        datalink.protocol = DatalinkProtocol::ETHERNET;
        datalink.header = header;

        // Check payload type.
        switch (header->ethertype) {
            case 0x0800: // IPv4
                network_type = NetworkProtocol::IPV4;
                break;
            case 0x86dd: // IPv6
                network_type = NetworkProtocol::IPV6;
                break;
            case 0x0806: // ARP
                network_type = NetworkProtocol::ARP;
                break;
        }
    } else {
        return datalink;
    }

    // Parse network layer.
    payload += datalink.header->header_length();
    NetworkPacket &network = datalink.payload;
    TransportProtocol transport_type = TransportProtocol::INVALID;
    int data_length = 0;
    switch (network_type) {
        case NetworkProtocol::IPV4: {
            auto header = new IPv4Header(IPv4Header::parse(payload));
            network.protocol = NetworkProtocol::IPV4;
            network.header = header;
            transport_type = Parser::ip_protocol(header->protocol);
            data_length = header->total_length - header->header_length();

            // Check DF and MF.
            int DF = (header->flags_frag_offset >> 14) & 0x01;
            int MF = (header->flags_frag_offset >> 13) & 0x01;
            int offset = (header->flags_frag_offset) & 0x1FFF;
            if (DF && MF) {
                transport_type = TransportProtocol::INVALID; // Mark as INVALID to stop parse.
                datalink.flag |= DatalinkFlag::IP_INCOMPLETE;

                // Check or create incomplete ip packets.
                if (!incomplete_ip_packets.contains(header->identification)) {
                    incomplete_ip_packets[header->identification] = IncompleteIPPacket();
                    IncompleteIPPacket &packet = incomplete_ip_packets[header->identification];

                    // Create a new packet.
                    packet.packet.header = new EthernetHeader(EthernetHeader::parse(bytes));
                    packet.packet.protocol = DatalinkProtocol::ETHERNET;
                    packet.packet.payload.header = new IPv4Header(IPv4Header::parse(payload));
                    packet.packet.payload.protocol = NetworkProtocol::IPV4;
                    packet.packet.payload.payload.protocol = Parser::ip_protocol(header->protocol);
                    packet.packet.flag = DatalinkFlag::IP_REASSEMBLED;
                }

                // Copy data.
                IncompleteIPPacket &packet = incomplete_ip_packets[header->identification];
                if (packet.data.size() < offset * 8 + data_length) {
                    packet.data.resize(offset * 8 + data_length, 0);
                }
                std::memcpy(packet.data.data() + offset * 8, payload + network.header->header_length(), data_length);
            } else if (DF && !MF && incomplete_ip_packets.contains(header->identification)) {
                transport_type = TransportProtocol::INVALID; // Mark as INVALID to stop parse.

                // Finish packet.
                IncompleteIPPacket &packet = incomplete_ip_packets[header->identification];
                additional = header->identification;

                // Copy data.
                if (packet.data.size() < offset * 8 + data_length) {
                    packet.data.resize(offset * 8 + data_length, 0);
                }
                std::memcpy(packet.data.data() + offset * 8, payload + network.header->header_length(), data_length);

                // Parse transport layer.
                TransportPacket &transport = packet.packet.payload.payload;
                switch (transport.protocol) {
                    case TransportProtocol::TCP: {
                        auto header = new TCPHeader(TCPHeader::parse(packet.data.data()));
                        transport.header = header;
                        break;
                    }
                    case TransportProtocol::UDP: {
                        auto header = new UDPHeader(UDPHeader::parse(packet.data.data()));
                        transport.header = header;
                        break;
                    }
                    case TransportProtocol::ICMP: {
                        /* ICMP Works in Network Layer, but it is packed by IP protocol. */
                        auto header = new ICMPPacket(ICMPPacket::parse(packet.data.data(), packet.data.size()));
                        transport.header = header;
                        return datalink;
                    }
                    default: {
                        return datalink;
                    }
                }

                // Parse application layer.
                if (data_length < 0) return this->packets[this->packets.size() - 2];
                transport.payload.payload.resize(data_length - transport.header->header_length());
                std::memcpy(
                    transport.payload.payload.data(),
                    packet.data.data() + transport.header->header_length(),
                    data_length - transport.header->header_length()
                );

                return datalink;
            }
            break;
        }
        case NetworkProtocol::IPV6: {
            auto header = new IPv6Header(IPv6Header::parse(payload));
            network.protocol = NetworkProtocol::IPV6;
            network.header = header;
            transport_type = Parser::ipv6_protocol(header->next_header);
            data_length = header->payload_length;
            break;
        }
        case NetworkProtocol::ARP: {
            auto packet = new ARPPacket(ARPPacket::parse(payload));
            network.protocol = NetworkProtocol::ARP;
            network.header = packet;
            return datalink;
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
        case TransportProtocol::UDP: {
            auto header = new UDPHeader(UDPHeader::parse(payload));
            transport.protocol = TransportProtocol::UDP;
            transport.header = header;
            break;
        }
        case TransportProtocol::ICMP: {
            /* ICMP Works in Network Layer, but it is packed by IP protocol. */
            auto packet = new ICMPPacket(ICMPPacket::parse(payload, data_length));
            transport.protocol = TransportProtocol::ICMP;
            transport.header = packet;
            return datalink;
        }
        case TransportProtocol::ICMPV6: {
            /* ICMP Works in Network Layer, but it is packed by IP protocol. */
            auto packet = new ICMPv6Packet(ICMPv6Packet::parse(payload, data_length));
            transport.protocol = TransportProtocol::ICMPV6;
            transport.header = packet;
            return datalink;
        }
        default: {
            return datalink;
        }
    }

    // Parse application layer.
    payload += transport.header->header_length();
    data_length -= transport.header->header_length();
    if (data_length < 0) return datalink;
    transport.payload.payload.resize(data_length);
    std::memcpy(transport.payload.payload.data(), payload, data_length);

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
        case IPPROTO_UDP: return TransportProtocol::UDP;
        case IPPROTO_ICMP: return TransportProtocol::ICMP;
        default: return TransportProtocol::INVALID;
    }
}

TransportProtocol Parser::ipv6_protocol(int next_header) {
    switch (next_header) {
        case 0x01: return TransportProtocol::ICMP;
        case 0x06: return TransportProtocol::TCP;
        case 0x11: return TransportProtocol::UDP;
        case 0x3a: return TransportProtocol::ICMPV6;
        default: return TransportProtocol::INVALID;
    }
}

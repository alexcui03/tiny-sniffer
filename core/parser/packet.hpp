#pragma once

#include <string>
#include <vector>
#include <utility>

#include <pcap.h>

struct PacketHeader {
    virtual size_t header_length() const { return 0; }
    virtual std::string to_string() const { return ""; }
    virtual std::string get_source() const { return ""; }
    virtual std::string get_destination() const { return ""; }
};

enum DatalinkFlag {
    IP_INCOMPLETE = 0x01,
    IP_REASSEMBLED = 0x02
};

enum class DatalinkProtocol {
    INVALID, ETHERNET
};

enum class NetworkProtocol {
    INVALID, IPV4, IPV6, ARP
};

enum class TransportProtocol {
    INVALID, TCP, UDP,
    ICMP, ICMPV6 /* ICMP Works in Network Layer, but it is packed by IP protocol. */
};

struct ApplicationPacket {
    std::vector<uint8_t> payload;

    std::string to_string() const;
};

struct TransportPacket {
    TransportProtocol protocol;
    PacketHeader *header = nullptr;
    ApplicationPacket payload;

    std::string to_string() const;
};

struct NetworkPacket {
    NetworkProtocol protocol;
    PacketHeader *header = nullptr;
    TransportPacket payload;

    std::string to_string() const;
    std::string get_source() const;
    std::string get_destination() const;
};

struct DatalinkPacket {
    DatalinkProtocol protocol;
    PacketHeader *header = nullptr;
    NetworkPacket payload;
    timeval timestamp;
    int flag = 0;

    std::string to_string() const;
    std::string get_time() const;
    std::string get_source() const;
    std::string get_destination() const;
    std::string get_protocol() const;
    std::string get_description() const;
    std::vector<std::pair<std::string, std::string>> get_contents() const;
};

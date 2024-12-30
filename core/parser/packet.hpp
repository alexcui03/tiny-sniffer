#pragma once

#include <string>

#include <pcap.h>

struct PacketHeader {
    virtual size_t header_length() const { return 0; }
    virtual std::string to_string() const { return ""; }
    virtual std::string get_source() const { return ""; }
    virtual std::string get_destination() const { return ""; }
};

enum class DatalinkProtocol {
    INVALID, ETHERNET
};

enum class NetworkProtocol {
    INVALID, IPV4, IPV6, ICMP, ARP
};

enum class TransportProtocol {
    INVALID, TCP, UDP
};

struct ApplicationPacket {
    uint8_t *payload = nullptr;
    size_t length;
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

    std::string to_string() const;
    std::string get_time() const;
    std::string get_source() const;
    std::string get_destination() const;
    std::string get_protocol() const;
};

#pragma once

#include <iostream>

struct PacketHeader {
    virtual size_t header_length() const { return 0; };
    virtual std::string to_string() const { return ""; };
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
};

struct DatalinkPacket {
    DatalinkProtocol protocol;
    PacketHeader *header = nullptr;
    NetworkPacket payload;

    std::string to_string() const;
};

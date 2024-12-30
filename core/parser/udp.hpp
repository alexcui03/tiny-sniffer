#pragma once

#include "packet.hpp"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

struct UDPHeader: public PacketHeader {
    uint16_t src_port;       // 源端口
    uint16_t dst_port;       // 目标端口
    uint16_t length;         // 长度
    uint16_t checksum;       // 校验和

    size_t header_length() const override {
        return 8;
    }

    std::string to_string() const override {
        std::stringstream stream;
        stream << "Source Port: " << src_port << std::endl;
        stream << "Destination Port: " << dst_port << std::endl;
        stream << "Length: " << length << std::endl;
        stream << "Checksum: " << std::hex << "0x" << checksum << std::dec << std::endl;

        return stream.str();
    }

    std::string get_source() const override {
        return std::to_string(this->src_port);
    }

    std::string get_destination() const override {
        return std::to_string(this->dst_port);
    }

    static UDPHeader parse(const uint8_t *bytes) {
        UDPHeader header;

        // 将字节数据复制到 UDP 结构体中
        header.src_port = ntohs(*(reinterpret_cast<const uint16_t*>(bytes)));          // 源端口
        header.dst_port = ntohs(*(reinterpret_cast<const uint16_t*>(bytes + 2)));      // 目标端口
        header.length = ntohs(*(reinterpret_cast<const uint16_t*>(bytes + 4)));        // 长度
        header.checksum = ntohs(*(reinterpret_cast<const uint16_t*>(bytes + 6)));      // 校验和

        return header;
    }
};

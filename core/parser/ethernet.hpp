#pragma once

#include "packet.hpp"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

// 定义以太网头部结构
struct EthernetHeader: public PacketHeader {
    uint8_t dest_mac[6];  // 目标 MAC 地址
    uint8_t src_mac[6];   // 源 MAC 地址
    uint16_t ethertype;   // EtherType 字段，2 字节

    size_t header_length() const override {
        return 14;
    }

    std::string to_string() const override {
        std::stringstream stream;
        stream << "Dest MAC: " << std::hex << std::setfill('0') << std::uppercase;
        stream << std::setw(2) << (int)dest_mac[0];
        for (size_t i = 1; i < 6; ++i) {
            stream << ":" << std::setw(2) << (int)dest_mac[i];
        }
        stream << "\nSrc MAC: ";
        stream << std::setw(2) << (int)src_mac[0];
        for (size_t i = 1; i < 6; ++i) {
            stream << ":" << std::setw(2) << (int)src_mac[i];
        }
        stream << "\nEth Type: 0x" << std::setw(4) << ethertype;
        return stream.str();
    }

    // 解析以太网头部
    static EthernetHeader parse(const uint8_t* data) {
        EthernetHeader header;
        std::memcpy(header.dest_mac, data, 6);            // 目标 MAC 地址
        std::memcpy(header.src_mac, data + 6, 6);         // 源 MAC 地址
        std::memcpy(&header.ethertype, data + 12, 2);     // EtherType
        return header;
    }
};

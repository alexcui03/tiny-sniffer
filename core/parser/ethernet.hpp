#pragma once

#include <cstdint>
#include <cstring>

// 定义以太网头部结构
struct EthernetHeader {
    uint8_t dest_mac[6];  // 目标 MAC 地址
    uint8_t src_mac[6];   // 源 MAC 地址
    uint16_t ethertype;   // EtherType 字段，2 字节

    // 解析以太网头部
    static EthernetHeader parse(const uint8_t* data) {
        EthernetHeader header;
        std::memcpy(header.dest_mac, data, 6);            // 目标 MAC 地址
        std::memcpy(header.src_mac, data + 6, 6);         // 源 MAC 地址
        std::memcpy(&header.ethertype, data + 12, 2);     // EtherType
        return header;
    }
};

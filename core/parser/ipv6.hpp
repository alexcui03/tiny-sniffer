#pragma once

#include <cstdint>
#include <cstring>

struct IPv6Header {
    uint32_t version_traffic_class_flow_label;  // 版本（4位）、流量类（8位）和标签（20位）
    uint16_t payload_length;                    // 有效载荷长度
    uint8_t next_header;                        // 下一个头部
    uint8_t hop_limit;                          // 跳数限制
    uint8_t src_ip[16];                         // 源 IP 地址
    uint8_t dest_ip[16];                        // 目标 IP 地址

    // 计算 IPv6 头部的字节长度
    static constexpr size_t header_length() {
        return 40;  // IPv6 头部固定为 40 字节
    }

    // 从字节流解析 IPv6 头部
    static IPv6Header parse(const uint8_t* data) {
        IPv6Header header;
        
        // 解析版本、流量类和标签
        std::memcpy(&header.version_traffic_class_flow_label, data, sizeof(header.version_traffic_class_flow_label));

        // 解析有效载荷长度、下一个头部和跳数限制
        std::memcpy(&header.payload_length, data + 4, sizeof(header.payload_length));
        std::memcpy(&header.next_header, data + 6, sizeof(header.next_header));
        std::memcpy(&header.hop_limit, data + 7, sizeof(header.hop_limit));

        // 解析源和目标 IP 地址
        std::memcpy(header.src_ip, data + 8, sizeof(header.src_ip));
        std::memcpy(header.dest_ip, data + 24, sizeof(header.dest_ip));

        return header;
    }
};

#pragma once

#include <cstdint>
#include <cstring>

struct IPv4Header {
    uint8_t version_ihl;        // 版本（4位）和头部长度（4位）
    uint8_t tos;                // 服务类型
    uint16_t total_length;      // 总长度
    uint16_t identification;    // 标识
    uint16_t flags_frag_offset; // 标志（3位）和片偏移（13位）
    uint8_t ttl;                // 生存时间
    uint8_t protocol;           // 协议
    uint16_t checksum;          // 头部校验和
    uint32_t src_ip;            // 源 IP 地址
    uint32_t dest_ip;           // 目标 IP 地址

    // 计算 IPv4 头部的字节长度
    static constexpr size_t header_length() {
        return 20;              // IPv4 头部固定为 20 字节（不包括选项）
    }

    // 从字节流解析 IPv4 头部
    static IPv4Header parse(const uint8_t* data) {
        IPv4Header header;
        std::memcpy(&header.version_ihl, data, sizeof(header.version_ihl));
        std::memcpy(&header.tos, data + 1, sizeof(header.tos));
        std::memcpy(&header.total_length, data + 2, sizeof(header.total_length));
        std::memcpy(&header.identification, data + 4, sizeof(header.identification));
        std::memcpy(&header.flags_frag_offset, data + 6, sizeof(header.flags_frag_offset));
        std::memcpy(&header.ttl, data + 8, sizeof(header.ttl));
        std::memcpy(&header.protocol, data + 9, sizeof(header.protocol));
        std::memcpy(&header.checksum, data + 10, sizeof(header.checksum));
        std::memcpy(&header.src_ip, data + 12, sizeof(header.src_ip));
        std::memcpy(&header.dest_ip, data + 16, sizeof(header.dest_ip));
        return header;
    }
};

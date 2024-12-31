#pragma once

#include "packet.hpp"

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

struct IPv4Header: public PacketHeader {
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
    size_t header_length() const override {
        return (version_ihl & 0x0F) * 4;
    }

    std::string to_string() const override {
        std::stringstream stream;
        uint8_t version = version_ihl >> 4;  // 版本
        uint8_t ihl = version_ihl & 0x0F;    // 头部长度
        stream << "Version: " << (int)version << ", IHL: " << (int)ihl << std::endl;
        stream << "TOS: " << (int)tos << std::endl;
        stream << "Total Length: " << total_length << std::endl;
        stream << "Identification: " << identification << std::endl;

        // 标志和片偏移
        uint16_t flags = flags_frag_offset >> 13;
        uint16_t frag_offset = flags_frag_offset & 0x1FFF;
        stream << "Flags: " << flags << "(DF="
            << (int)((flags >> 1) & 0x01) << ", MF=" <<  (int)(flags & 0x01)
            << "), Fragment Offset: " << frag_offset << std::endl;

        stream << "TTL: " << (int)ttl << std::endl;
        stream << "Protocol: " << (int)protocol << std::endl;
        stream << "Checksum: " << checksum << std::endl;

        // 打印 IP 地址
        stream << "Source IP: " << ip_to_string(src_ip) << std::endl;
        stream << "Destination IP: " << ip_to_string(dest_ip);

        return stream.str();
    }

    std::string get_source() const override {
        return ip_to_string(this->src_ip);
    }

    std::string get_destination() const override {
        return ip_to_string(this->dest_ip);
    }

    static std::string ip_to_string(uint32_t ip) {
        return std::to_string((ip >> 24) & 0xFF) + "."
            + std::to_string((ip >> 16) & 0xFF) + "."
            + std::to_string((ip >> 8) & 0xFF) + "."
            + std::to_string(ip & 0xFF);
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
        header.total_length = ntohs(header.total_length);
        header.identification = ntohs(header.identification);
        header.flags_frag_offset = ntohs(header.flags_frag_offset);
        header.checksum = ntohs(header.checksum);
        header.src_ip = ntohl(header.src_ip);
        header.dest_ip = ntohl(header.dest_ip);
        return header;
    }
};

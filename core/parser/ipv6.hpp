#pragma once

#include "packet.hpp"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

struct IPv6Header: public PacketHeader {
    uint32_t version_traffic_class_flow_label;  // 版本（4位）、流量类（8位）和标签（20位）
    uint16_t payload_length;                    // 有效载荷长度
    uint8_t next_header;                        // 下一个头部
    uint8_t hop_limit;                          // 跳数限制
    uint8_t src_ip[16];                         // 源 IP 地址
    uint8_t dest_ip[16];                        // 目标 IP 地址

    // 计算 IPv6 头部的字节长度
    size_t header_length() const override {
        return 40;  // IPv6 头部固定为 40 字节
    }

    std::string to_string() const override {
        std::stringstream stream;
        // 提取版本、流量类和标签
        uint8_t version = (version_traffic_class_flow_label >> 28) & 0x0F;
        uint8_t traffic_class = (version_traffic_class_flow_label >> 20) & 0xFF;
        uint32_t flow_label = version_traffic_class_flow_label & 0xFFFFF;

        stream << "Version: " << (int)version << ", Traffic Class: " << (int)traffic_class
                  << ", Flow Label: " << flow_label << std::endl;

        stream << "Payload Length: " << payload_length << std::endl;
        stream << "Next Header: " << (int)next_header << std::endl;
        stream << "Hop Limit: " << (int)hop_limit << std::endl;

        // 打印源 IP 地址
        stream << "Source IP: " << std::hex << std::uppercase;
        for (int i = 0; i < 16; ++i) {
            if (src_ip[i] > 0) stream << src_ip[i];
            if (i < 15) stream << ":";
        }
        stream << std::endl;

        // 打印目标 IP 地址
        stream << "Destination IP: ";
        for (int i = 0; i < 16; ++i) {
            if (dest_ip[i] > 0) stream << dest_ip[i];
            if (i < 15) stream << ":";
        }

        return stream.str();
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

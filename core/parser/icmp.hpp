#pragma once

#include "packet.hpp"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

struct ICMPPacket: public PacketHeader {
    uint8_t type;        // ICMP 类型
    uint8_t code;        // ICMP 代码
    uint16_t checksum;   // 校验和
    std::vector<uint8_t> data;

    size_t header_length() const override {
        return 4;
    }

    std::string to_string() const override {
        std::stringstream stream;
        stream << "ICMP Type: " << (int)type << std::endl;
        stream << "ICMP Code: " << (int)code << std::endl;
        stream << "Checksum: 0x" << std::hex << std::setfill('0') << std::setw(4) << checksum << std::endl;

        // 打印数据部分（以十六进制格式）
        stream << "Data:" << std::hex << std::setfill('0') << std::endl;
        for (size_t i = 0; i < data.size(); i++) {
            stream << std::setw(2)<< (int)data[i] << " ";
        }

        return stream.str();
    }

    static ICMPPacket parse(const uint8_t *bytes, size_t length) {
        ICMPPacket icmpPacket;

        icmpPacket.type = bytes[0];       // ICMP 类型字段
        icmpPacket.code = bytes[1];       // ICMP 代码字段
        icmpPacket.checksum = (bytes[2] << 8) | bytes[3];  // 校验和（大端序）
        
        // 数据部分：数据从 ICMP 头部之后开始
        icmpPacket.data.resize(length - 4);
        std::memcpy(icmpPacket.data.data(), bytes + 4, length - 4);

        return icmpPacket;
    }
};
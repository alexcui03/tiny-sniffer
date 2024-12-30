#pragma once

#include "packet.hpp"

#include <cstdint>
#include <cstring>
#include <vector>
#include <iomanip>
#include <sstream>
#include <string>

// 定义 TCP 数据包头部结构
struct TCPHeader: public PacketHeader {
    uint16_t src_port;        // 源端口
    uint16_t dest_port;       // 目标端口
    uint32_t seq_number;      // 序列号
    uint32_t ack_number;      // 确认号
    uint16_t data_offset_flags; // 数据偏移（4位）+ 保留字段（3位）+ 控制位（9位）
    uint16_t window_size;     // 窗口大小
    uint16_t checksum;        // 校验和
    uint16_t urgent_pointer;  // 紧急指针
    // 可选的 TCP 选项数据（如果存在）
    std::vector<uint8_t> options;

    // 计算 TCP 头部的长度
    size_t header_length() const override {
        return (this->data_offset_flags >> 12) * 4;
    }

    std::string to_string() const override {
        std::stringstream stream;
        stream << "Source Port: " << src_port << std::endl;
        stream << "Destination Port: " << dest_port << std::endl;
        stream << "Sequence Number: " << seq_number << std::endl;
        stream << "Acknowledgment Number: " << ack_number << std::endl;

        // 数据偏移字段
        uint8_t data_offset = (data_offset_flags >> 12) & 0x0F;
        stream << "Data Offset: " << (int)data_offset << " (";
        stream << (data_offset * 4) << " bytes)" << std::endl;

        // 标志字段（使用控制位的高 9 位）
        uint8_t urg = (data_offset_flags >> 7) & 0x01;
        uint8_t ack = (data_offset_flags >> 6) & 0x01;
        uint8_t psh = (data_offset_flags >> 5) & 0x01;
        uint8_t rst = (data_offset_flags >> 4) & 0x01;
        uint8_t syn = (data_offset_flags >> 3) & 0x01;
        uint8_t fin = (data_offset_flags >> 2) & 0x01;

        stream << "Flags: ";
        stream << "URG=" << (int)urg << ", ";
        stream << "ACK=" << (int)ack << ", ";
        stream << "PSH=" << (int)psh << ", ";
        stream << "RST=" << (int)rst << ", ";
        stream << "SYN=" << (int)syn << ", ";
        stream << "FIN=" << (int)fin << std::endl;

        stream << "Window Size: " << window_size << std::endl;
        stream << "Checksum: " << checksum << std::endl;
        stream << "Urgent Pointer: " << urgent_pointer;

        // 打印 TCP 选项（如果有的话）
        if (!options.empty()) {
            stream << "\nOptions: " << std::hex << std::uppercase << std::setfill('0');
            for (size_t i = 0; i < options.size(); ++i) {
                stream << std::setw(2) << options[i] << ' ';
            }
        }

        return stream.str();
    }

    // 从字节流中解析 TCP 头部
    static TCPHeader parse(const uint8_t* data) {
        TCPHeader header;

        // 解析基础字段
        std::memcpy(&header.src_port, data, sizeof(header.src_port));
        std::memcpy(&header.dest_port, data + 2, sizeof(header.dest_port));
        std::memcpy(&header.seq_number, data + 4, sizeof(header.seq_number));
        std::memcpy(&header.ack_number, data + 8, sizeof(header.ack_number));
        std::memcpy(&header.data_offset_flags, data + 12, sizeof(header.data_offset_flags));
        std::memcpy(&header.window_size, data + 14, sizeof(header.window_size));
        std::memcpy(&header.checksum, data + 16, sizeof(header.checksum));
        std::memcpy(&header.urgent_pointer, data + 18, sizeof(header.urgent_pointer));

        // 计算 TCP 头部长度（数据偏移字段指示头部长度，单位是 4 字节）
        size_t header_len = (header.data_offset_flags >> 12) * 4; // 因为 data_offset 是 4 位的
        if (header_len > 20) {
            // 如果存在 TCP 选项，读取选项部分
            header.options.resize(header_len - 20);
            std::memcpy(header.options.data(), data + 20, header.options.size());
        }

        return header;
    }
};

#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

// 定义 TCP 数据包头部结构
struct TCPHeader {
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
    size_t header_length() {
        return (this->data_offset_flags >> 12) * 4;
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

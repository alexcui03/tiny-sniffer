#pragma once

#include "packet.hpp"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

// ARP报文的硬件类型常量
#define ARP_HW_TYPE_ETHERNET 1
// ARP 操作类型常量
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

// ARP 数据包结构体定义
struct ARPPacket: public PacketHeader {
    uint16_t hw_type;            // 硬件类型 (Ethernet = 1)
    uint16_t proto_type;         // 协议类型 (IPv4 = 0x0800)
    uint8_t hw_len;              // 硬件地址长度 (Ethernet = 6)
    uint8_t proto_len;           // 协议地址长度 (IPv4 = 4)
    uint16_t operation;          // 操作类型 (1 = 请求, 2 = 回复)
    uint8_t sender_hw_addr[6];   // 发送者硬件地址 (MAC)
    uint8_t sender_ip_addr[4];   // 发送者协议地址 (IP)
    uint8_t target_hw_addr[6];   // 目标硬件地址 (MAC)
    uint8_t target_ip_addr[4];   // 目标协议地址 (IP)

    size_t header_length() const override {
        return 28;
    }

    // 输出 ARP 数据包的解析结果
    std::string to_string() const override {
        std::stringstream stream;
        // 打印硬件类型、协议类型等信息
        stream << "Hardware Type: " << (hw_type) << std::endl;
        stream << "Protocol Type: " << (proto_type) << std::endl;
        stream << "Hardware Length: " << (int)hw_len << std::endl;
        stream << "Protocol Length: " << (int)proto_len << std::endl;
        stream << "Operation: " << (operation) << std::endl;

        // 打印发送者的 MAC 地址
        stream << "Sender MAC Address: " << mac_to_string(sender_hw_addr) << std::endl;

        // 打印发送者的 IP 地址
        stream << "Sender IP Address: " << ip_to_string(sender_ip_addr) << std::endl;

        // 打印目标的 MAC 地址
        stream << "Target MAC Address: " << mac_to_string(target_hw_addr) << std::endl;

        // 打印目标的 IP 地址
        stream << "Target IP Address: " << ip_to_string(target_ip_addr) << std::endl;

        return stream.str();
    }

    std::string get_source() const override {
        return ip_to_string(sender_ip_addr);
    }

    std::string get_destination() const override {
        return ip_to_string(target_ip_addr);
    }

    static std::string mac_to_string(const uint8_t mac[6]) {
        std::stringstream stream;
        stream << std::hex << std::setfill('0') << std::uppercase;
         for (size_t i = 0; i < 6; ++i) {
            if (i > 0) stream << ":";
            stream << std::setw(2) << (int)mac[i];
        }
        return stream.str();
    }

    static std::string ip_to_string(const uint8_t ip[4]) {
        std::stringstream stream;
        stream << std::dec;
        for (int i = 0; i < 4; ++i) {
            stream << (int)ip[i];
            if (i < 3) stream << ".";
        }
        return stream.str();
    }

    static ARPPacket parse(const uint8_t *bytes) {
        ARPPacket arp;
        std::memcpy(&arp.hw_type, bytes, sizeof(arp.hw_type));
        std::memcpy(&arp.proto_type, bytes + 2, sizeof(arp.proto_type));
        std::memcpy(&arp.hw_len, bytes + 4, sizeof(arp.hw_len));
        std::memcpy(&arp.proto_len, bytes + 5, sizeof(arp.proto_len));
        std::memcpy(&arp.operation, bytes + 6, sizeof(arp.operation));
        std::memcpy(&arp.sender_hw_addr, bytes + 8, sizeof(arp.sender_hw_addr));
        std::memcpy(&arp.sender_ip_addr, bytes + 14, sizeof(arp.sender_ip_addr));
        std::memcpy(&arp.target_hw_addr, bytes + 18, sizeof(arp.target_hw_addr));
        std::memcpy(&arp.target_ip_addr, bytes + 24, sizeof(arp.target_ip_addr));

        arp.hw_type = ntohs(arp.hw_type);
        arp.proto_type = ntohs(arp.proto_type);
        arp.operation = ntohs(arp.operation);
        return arp;
    }
};

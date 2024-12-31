#include "packet.hpp"

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

#include "ethernet.hpp"

std::string DatalinkPacket::to_string() const {
    std::string result = this->payload.to_string();
    if (this->header) {
        result = this->header->to_string() +  + "\n----------\n" + result;
    }
    return result;
}

std::string DatalinkPacket::get_time() const {
    time_t seconds = timestamp.tv_sec;
    tm *timeinfo = localtime(&seconds);
    char buffer[100];
    strftime(buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", timeinfo);
    sprintf(buffer + 19, ".%03d", timestamp.tv_usec / 1000);
    return buffer;
}

std::string DatalinkPacket::get_source() const {
    if (protocol == DatalinkProtocol::ETHERNET) {
        if (payload.protocol == NetworkProtocol::IPV4 ||
            payload.protocol == NetworkProtocol::IPV6
        ) {
            return payload.get_source();
        }
    }
    return header->get_source();
}

std::string DatalinkPacket::get_description() const {
    if (flag & DatalinkFlag::IP_INCOMPLETE) {
        return "Incomplete IP Packet";
    }
    if (flag & DatalinkFlag::IP_REASSEMBLED) {
        return "Dummy reassembled IP Packet";
    }
    return "";
}

std::string DatalinkPacket::get_destination() const {
    if (protocol == DatalinkProtocol::ETHERNET) {
        if (payload.protocol == NetworkProtocol::IPV4 ||
            payload.protocol == NetworkProtocol::IPV6
        ) {
            return payload.get_destination();
        }
        return header->get_destination();
    }
    return header->get_destination();
}

std::string DatalinkPacket::get_protocol() const {
    if (protocol == DatalinkProtocol::ETHERNET) {
        if (payload.protocol == NetworkProtocol::IPV4 ||
            payload.protocol == NetworkProtocol::IPV6
        ) {
            switch (payload.payload.protocol) {
                case TransportProtocol::TCP: return "TCP";
                case TransportProtocol::UDP: return "UDP";
                case TransportProtocol::ICMP: return "ICMP";
                case TransportProtocol::ICMPV6: return "ICMP";
            }
            return "IP";
        } else if (payload.protocol == NetworkProtocol::ARP) {
            return "ARP";
        }
        return "ETHERNET";
    }
    return "UNKNOWN";
}

std::string NetworkPacket::to_string() const {
    std::string result = this->payload.to_string();
    if (this->header) {
        result = this->header->to_string() +  + "\n----------\n" + result;
    }
    return result;
}

std::string NetworkPacket::get_source() const {
    if (protocol == NetworkProtocol::IPV4) {
        if (payload.protocol == TransportProtocol::TCP ||
            payload.protocol == TransportProtocol::UDP
        ) {
            return header->get_source() + ":" + payload.header->get_source();
        }
    }
    if (protocol == NetworkProtocol::IPV6) {
        if (payload.protocol == TransportProtocol::TCP ||
            payload.protocol == TransportProtocol::UDP
        ) {
            return "[" + header->get_source() + "]:" + payload.header->get_source();
        }
    }
    return header->get_source();
}

std::string NetworkPacket::get_destination() const {
    if (protocol == NetworkProtocol::IPV4) {
        if (payload.protocol == TransportProtocol::TCP ||
            payload.protocol == TransportProtocol::UDP
        ) {
            return header->get_destination() + ":" + payload.header->get_destination();
        }
    }
    if (protocol == NetworkProtocol::IPV6) {
        if (payload.protocol == TransportProtocol::TCP ||
            payload.protocol == TransportProtocol::UDP
        ) {
            return "[" + header->get_destination() + "]:" + payload.header->get_destination();
        }
    }
    return header->get_destination();
}

std::string TransportPacket::to_string() const {
    if (this->header) {
        return this->header->to_string() +  + "\n----------\n" + this->payload.to_string();
    }
    return "";
}

std::string ApplicationPacket::to_string() const {
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < payload.size(); ++i) {
        if (i > 0) stream << ' ';
        stream << std::setw(2) << static_cast<int>(payload[i]);
    }
    return stream.str();
}

std::vector<std::pair<std::string, std::string>> DatalinkPacket::get_contents() const {
    std::vector<std::pair<std::string, std::string>> result;

    if (this->protocol == DatalinkProtocol::ETHERNET) {
        auto &pair = result.emplace_back();
        pair.first = "ETHERNET";
        pair.second = this->header->to_string();
    } else {
        return result;
    }

    auto &network = this->payload;
    if (network.protocol == NetworkProtocol::IPV4) {
        auto &pair = result.emplace_back();
        pair.first = "IP";
        pair.second = network.header->to_string();
    } else if (network.protocol == NetworkProtocol::IPV6) {
        auto &pair = result.emplace_back();
        pair.first = "IPv6";
        pair.second = network.header->to_string();
    } else if (network.protocol == NetworkProtocol::ARP) {
        auto &pair = result.emplace_back();
        pair.first = "ARP";
        pair.second = network.header->to_string();
        return result;
    } else {
        return result;
    }

    auto &transport = network.payload;
    if (transport.protocol == TransportProtocol::TCP) {
        auto &pair = result.emplace_back();
        pair.first = "TCP";
        pair.second = transport.header->to_string();
    } else if (transport.protocol == TransportProtocol::UDP) {
        auto &pair = result.emplace_back();
        pair.first = "UDP";
        pair.second = transport.header->to_string();
    } else if (transport.protocol == TransportProtocol::ICMP) {
        auto &pair = result.emplace_back();
        pair.first = "ICMP";
        pair.second = transport.header->to_string();
        return result;
    } else if (transport.protocol == TransportProtocol::ICMPV6) {
        auto &pair = result.emplace_back();
        pair.first = "ICMPv6";
        pair.second = transport.header->to_string();
        return result;
    } else {
        return result;
    }

    auto &application = transport.payload;
    auto &pair = result.emplace_back();
    pair.first = "Application";
    pair.second = application.to_string();

    return result;
}

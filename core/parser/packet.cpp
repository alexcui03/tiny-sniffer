#include "packet.hpp"

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

std::string binary_to_string(uint8_t *bytes, size_t length) {
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        if (i > 0) stream << ' ';
        stream << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return stream.str();
}

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
            }
            return "IP";
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
        if (payload.protocol == TransportProtocol::TCP) {
            return header->get_source() + ":" + payload.header->get_source();
        }
    }
    if (protocol == NetworkProtocol::IPV6) {
        if (payload.protocol == TransportProtocol::TCP) {
            return "[" + header->get_source() + "]:" + payload.header->get_source();
        }
    }
    return header->get_source();
}

std::string NetworkPacket::get_destination() const {
    if (protocol == NetworkProtocol::IPV4) {
        if (payload.protocol == TransportProtocol::TCP) {
            return header->get_destination() + ":" + payload.header->get_destination();
        }
    }
    if (protocol == NetworkProtocol::IPV6) {
        if (payload.protocol == TransportProtocol::TCP) {
            return "[" + header->get_destination() + "]:" + payload.header->get_destination();
        }
    }
    return header->get_destination();
}

std::string TransportPacket::to_string() const {
    std::string result = binary_to_string(this->payload.payload, this->payload.length);
    result = std::to_string(this->payload.length) + "\n" + result;
    if (this->header) {
        result = this->header->to_string() +  + "\n----------\n" + result;
    }
    return result;
}

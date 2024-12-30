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

std::string NetworkPacket::to_string() const {
    std::string result = this->payload.to_string();
    if (this->header) {
        result = this->header->to_string() +  + "\n----------\n" + result;
    }
    return result;
}

std::string TransportPacket::to_string() const {
    std::string result = binary_to_string(this->payload.payload, this->payload.length);
    result = std::to_string(this->payload.length) + "\n" + result;
    if (this->header) {
        result = this->header->to_string() +  + "\n----------\n" + result;
    }
    return result;
}

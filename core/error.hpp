#pragma once

#include <stdexcept>
#include <string>

class pcap_error: public std::runtime_error {
public:
    explicit pcap_error(const std::string &what): std::runtime_error(what) {};
    explicit pcap_error(const char *what): std::runtime_error(what) {};
};

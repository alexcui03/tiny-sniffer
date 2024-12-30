#pragma once

#include <functional>
#include <string>
#include <vector>

#include <pcap.h>

using UserCallbackType = std::function<void(const pcap_pkthdr *, const unsigned char *)>;

struct HandlerParams {
    UserCallbackType user_callback;
    int datalink;
};

class Device {
    std::string name;
    std::string description;
    mutable pcap_t *handle = nullptr;
public:
    Device(pcap_if_t *device);
    Device(const Device &other) = default;
    Device(Device &&other) = default;
    ~Device();
    inline std::string get_name() const { return this->name; }
    inline std::string get_description() const { return this->description; }
    void listen(UserCallbackType callback) const;
    void stop_listen() const;
    static std::vector<Device> get_device_list();
};

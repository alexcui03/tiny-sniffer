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
public:
    Device(pcap_if_t *device);
    ~Device();
    inline std::string get_name() const { return this->name; }
    inline std::string get_description() const { return this->description; }
    void listen(UserCallbackType callback) const;
    // void listen_async(UserCallbackType callback);
    static std::vector<Device> get_device_list();
};

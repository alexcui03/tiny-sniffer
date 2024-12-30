#include "device.hpp"

#include "error.hpp"

static void package_handler(u_char *user, const pcap_pkthdr *header, const u_char *bytes) {
	HandlerParams *params = reinterpret_cast<HandlerParams *>(user);
	params->user_callback(header, bytes);
}

Device::Device(pcap_if_t *device): name(device->name), description(device->description) {}

Device::~Device() {}

void Device::listen(UserCallbackType callback) const {
	char pcap_errbuf[PCAP_ERRBUF_SIZE];

	bpf_u_int32 srcip, netmask;
	if (pcap_lookupnet(this->name.c_str(), &srcip, &netmask, pcap_errbuf) == PCAP_ERROR) {
		throw pcap_error(pcap_errbuf);
	}

	pcap_t *handle = pcap_open_live(this->name.c_str(), BUFSIZ, 1, 1000, pcap_errbuf);
	if (handle == nullptr) {
        throw pcap_error(pcap_errbuf);
	}

	HandlerParams params;
	params.datalink = pcap_datalink(handle);
	params.user_callback = callback;

	if (pcap_loop(handle, 0, package_handler, reinterpret_cast<u_char *>(&params)) == PCAP_ERROR) {
        throw pcap_error(pcap_geterr(handle));
	}
}

std::vector<Device> Device::get_device_list() {
	std::vector<Device> result;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *all_devices = nullptr;
	if (pcap_findalldevs(&all_devices, pcap_errbuf) == PCAP_ERROR) {
		throw std::runtime_error(pcap_errbuf);
	}

    pcap_if_t *next_device = all_devices;
	while (next_device) {
        result.emplace_back(next_device);
        next_device = next_device->next;
	}

	pcap_freealldevs(all_devices);

	return result;
}

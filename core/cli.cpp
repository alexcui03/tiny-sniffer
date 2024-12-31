#include <iostream>

#include "tiny-sniffer.hpp"

int main(int argc, char *argv[]) {
    auto devices = Device::get_device_list();
	for (int i = 0; const auto &device : devices) {
		std::cout << "[" << i++ << "]" << device.get_name() << ": " << device.get_description() << std::endl;
	}

	int index;
	std::cout << "The index of device to listen to: ";
	std::cin >> index;

	Parser parser;

	devices[index].listen([&parser](const pcap_pkthdr *header, const unsigned char *bytes) {
		int additional = -1;
		decltype(auto) packet = parser.next_packet(header, bytes, additional);
        std::cout << "==========" << std::endl << packet.to_string() << std::endl;

		if (additional != -1) {
			decltype(auto) packet = parser.assembled_packet(additional);
			std::cout << "==========" << std::endl << packet.to_string() << std::endl;
		}
	});

    return 0;
}

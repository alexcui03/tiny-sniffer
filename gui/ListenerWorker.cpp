#include "ListenerWorker.hpp"

#include <functional>

ListenerWorker::ListenerWorker(const Device &device, QObject *parent)
    : QThread(parent), device(device) {}

ListenerWorker::~ListenerWorker() {}

void ListenerWorker::run() {
    using namespace std::placeholders;
    device.listen(std::bind(&ListenerWorker::deviceHandler, this, _1, _2));
}

void ListenerWorker::deviceHandler(const pcap_pkthdr *header, const unsigned char *bytes) {
    if (!paused) {
        int additional = -1;
        const DatalinkPacket &packet = parser.next_packet(header, bytes, additional);
        emit nextPacket(packet);

        if (additional != -1) {
            emit nextPacket(parser.assembled_packet(additional));
        }
    }
}

void ListenerWorker::pause() {
    paused = true;
}

void ListenerWorker::unpause() {
    paused = false;
}

void ListenerWorker::unlisten() {
    device.stop_listen();
}

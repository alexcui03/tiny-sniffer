#pragma once

#include <QThread>

#include "../core/tiny-sniffer.hpp"

class ListenerWorker: public QThread {
    Q_OBJECT
public:
    ListenerWorker(const Device &device, QObject *parent = nullptr);
    ~ListenerWorker();
    void unlisten();
protected:
    void run() override;
    void deviceHandler(const pcap_pkthdr *header, const unsigned char *bytes);
signals:
    void nextPacket(const DatalinkPacket &packet);
private:
    Device device;
    Parser parser;
};

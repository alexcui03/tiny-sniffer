#pragma once

#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPushButton>
#include <QResizeEvent>
#include <QSplitter>
#include <QStandardItemModel>
#include <QTableView>

#include <vector>

#include "../core/tiny-sniffer.hpp"
#include "ListenerWorker.hpp"
#include "MultipleFilterProxyModel.hpp"

enum PacketModel {
    Time, Source, Destination, Protocol, Description
};

class MainWindow: public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void invalidFilter();
public slots:
    void updateDevicesList();
    void startRecord();
    void pauseRecord();
    void stopRecord();
    void packetHandler(const DatalinkPacket &packet);
    void tableFilter();
protected:
    void resizeEvent(QResizeEvent *event) override;
protected:
    QSplitter vertical_splitter;
    QComboBox device_selector;
    QPushButton record_btn;
    QPushButton stop_btn;
    QLineEdit filter;
    QPushButton filter_btn;
    QTableView table_view;
    QLabel label;

    std::vector<Device> device_list;
    QStandardItemModel data;
    MultipleFilterProxyModel filter_data;
    ListenerWorker *worker = nullptr;
    bool record_started = false;
};

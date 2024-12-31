#pragma once

#include <QComboBox>
#include <QLineEdit>
#include <QMainWindow>
#include <QMetaType>
#include <QPushButton>
#include <QResizeEvent>
#include <QSplitter>
#include <QStandardItemModel>
#include <QTableView>
#include <QVector>
#include <QPair>
#include <QLabel>

#include <vector>

#include "../core/tiny-sniffer.hpp"
#include "ListenerWorker.hpp"
#include "PacketDetail.hpp"
#include "MultipleFilterProxyModel.hpp"
#include "utils.hpp"

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
    void clearRecord();
    void packetHandler(const DatalinkPacket &packet);
    void tableFilter();
    void onTableSelected();
protected:
    void resizeEvent(QResizeEvent *event) override;
protected:
    QSplitter vertical_splitter;
    QComboBox device_selector;
    QPushButton record_btn;
    QPushButton stop_btn;
    QPushButton clear_btn;
    QLineEdit filter;
    QPushButton filter_btn;
    QTableView table_view;
    PacketDetail packet_detail;

    std::vector<Device> device_list;
    QStandardItemModel data;
    MultipleFilterProxyModel filter_data;
    ListenerWorker *worker = nullptr;
    bool record_started = false;
};

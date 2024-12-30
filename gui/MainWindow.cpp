#include "MainWindow.hpp"

#include <QHeaderView>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), device_selector(this), record_btn(this), stop_btn(this),
    filter(this), filter_btn(this), data(this), filter_data(this),
    vertical_splitter(Qt::Vertical, this), table_view(&vertical_splitter), label(&vertical_splitter)
{
    this->setMinimumSize(800, 600);

    record_btn.setText("Start");
    record_btn.setEnabled(true);
    connect(&record_btn, &QPushButton::clicked, this, &MainWindow::startRecord);

    stop_btn.setText("Stop");
    stop_btn.setEnabled(false);
    connect(&stop_btn, &QPushButton::clicked, this, &MainWindow::stopRecord);

    filter.setPlaceholderText("Filter Patterns");

    filter_btn.setText("Search");
    connect(&filter_btn, &QPushButton::clicked, this, &MainWindow::tableFilter);

    // Init data
    data.insertColumns(0, 5);
    data.setHeaderData(PacketModel::Time, Qt::Horizontal, "Time");
    data.setHeaderData(PacketModel::Source, Qt::Horizontal, "Source");
    data.setHeaderData(PacketModel::Destination, Qt::Horizontal, "Destination");
    data.setHeaderData(PacketModel::Protocol, Qt::Horizontal, "Protocol");
    data.setHeaderData(PacketModel::Description, Qt::Horizontal, "Description");

    filter_data.setSourceModel(&data);

    table_view.setModel(&filter_data);
    table_view.horizontalHeader()->setStretchLastSection(true);
    table_view.verticalHeader()->hide();
    table_view.setEditTriggers(QTableView::NoEditTriggers);

    this->updateDevicesList();
}

MainWindow::~MainWindow() {}

void MainWindow::updateDevicesList() {
    this->device_list = Device::get_device_list();

    // Check if device selector has data.
    QString last_selected = "";
    if (device_selector.currentIndex() > 0) {
        last_selected = device_selector.currentText();
    }

    QStringList items;
    int new_index = -1;
    for (int i = 0; const auto &device : this->device_list) {
        auto text = QString::fromStdString(device.get_description());
        if (text == last_selected) {
            new_index = i;
        }

        items.push_back(text);
        ++i;
    }
    device_selector.clear();
    device_selector.addItems(items);

    if (new_index > 0) {
        device_selector.setCurrentIndex(new_index);
    }
}

void MainWindow::startRecord() {
    if (record_started) {
        this->pauseRecord();
        return;
    }

    if (worker == nullptr && device_selector.currentIndex() >= 0) {
        auto &device = device_list[device_selector.currentIndex()];
        worker = new ListenerWorker(device, this);
        connect(worker, &ListenerWorker::nextPacket, this, &MainWindow::packetHandler);
        worker->start();
    } else if (worker) {
        worker->unpause();
    }

    record_started = true;
    record_btn.setText("Pause");
    stop_btn.setEnabled(true);
    device_selector.setEnabled(false);
}

void MainWindow::pauseRecord() {
    if (worker) {
        worker->pause();
    }

    record_started = false;
    record_btn.setText("Unpause");
    stop_btn.setEnabled(false);
}

void MainWindow::stopRecord() {
    if (worker) {
        worker->unlisten();
        worker->wait();
        delete worker;
        worker = nullptr;
    }

    record_started = false;
    record_btn.setText("Start");
    stop_btn.setEnabled(false);
    device_selector.setEnabled(true);
}

void MainWindow::packetHandler(const DatalinkPacket &packet) {
    int row = data.rowCount();
    data.insertRow(row);
    data.setData(data.index(row, PacketModel::Time), QString::fromStdString(packet.get_time()));
    data.setData(data.index(row, PacketModel::Source), QString::fromStdString(packet.get_source()));
    data.setData(data.index(row, PacketModel::Destination), QString::fromStdString(packet.get_destination()));
    data.setData(data.index(row, PacketModel::Protocol), QString::fromStdString(packet.get_protocol()));
    data.setData(data.index(row, PacketModel::Description), "");
}

void MainWindow::resizeEvent(QResizeEvent *event) {
    const QSize new_size = event->size();

    device_selector.setGeometry(10, 10, 320, 30);
    record_btn.setGeometry(330, 10, 60, 30);
    stop_btn.setGeometry(390, 10, 60, 30);
    filter.setGeometry(10, 42, new_size.width() - 80, 26);
    filter_btn.setGeometry(new_size.width() - 70, 40, 60, 30);

    vertical_splitter.setGeometry(10, 80, new_size.width() - 20, new_size.height() - 90);
}

void MainWindow::invalidFilter() {
    // TODO
}

void MainWindow::tableFilter() {
    QString pattern = filter.text().trimmed();
    bool result = filter_data.setFilterPatten(pattern);
    if (!result) {
        this->invalidFilter();
    }
}

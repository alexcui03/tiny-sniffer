#include "MainWindow.hpp"

#include <QHeaderView>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), device_selector(this), record_btn(this), stop_btn(this), export_btn(this),
    filter(this), filter_btn(this), data(this), filter_data(this), clear_btn(this),
    vertical_splitter(Qt::Vertical, this), table_view(&vertical_splitter), packet_detail(&vertical_splitter)
{
    this->setMinimumSize(800, 600);

    record_btn.setText("Start");
    record_btn.setEnabled(true);
    connect(&record_btn, &QPushButton::clicked, this, &MainWindow::startRecord);

    stop_btn.setText("Stop");
    stop_btn.setEnabled(false);
    connect(&stop_btn, &QPushButton::clicked, this, &MainWindow::stopRecord);

    clear_btn.setText("Clear");
    connect(&clear_btn, &QPushButton::clicked, this, &MainWindow::clearRecord);

    export_btn.setText("Export");
    connect(&export_btn, &QPushButton::clicked, this, &MainWindow::exportRecord);

    filter.setPlaceholderText("Filter Patterns");

    filter_btn.setText("Search");
    connect(&filter_btn, &QPushButton::clicked, this, &MainWindow::tableFilter);

    // Init data
    data.insertColumns(0, 6);
    data.setHeaderData(PacketModel::Time, Qt::Horizontal, "Time");
    data.setHeaderData(PacketModel::Source, Qt::Horizontal, "Source");
    data.setHeaderData(PacketModel::Destination, Qt::Horizontal, "Destination");
    data.setHeaderData(PacketModel::Protocol, Qt::Horizontal, "Protocol");
    data.setHeaderData(PacketModel::Description, Qt::Horizontal, "Description");
    data.setHeaderData(PacketModel::Content, Qt::Horizontal, "Content");

    filter_data.setSourceModel(&data);

    table_view.setModel(&filter_data);
    table_view.horizontalHeader()->setStretchLastSection(true);
    table_view.verticalHeader()->hide();
    table_view.setEditTriggers(QTableView::NoEditTriggers);
    table_view.setColumnHidden(PacketModel::Content, true);
    connect(table_view.selectionModel(), &QItemSelectionModel::selectionChanged, this, &MainWindow::onTableSelected);

    this->updateDevicesList();
}

MainWindow::~MainWindow() {
    if (worker) {
        this->stopRecord();
    }
}

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

void MainWindow::clearRecord() {
    data.removeRows(0, data.rowCount());
}

void MainWindow::exportRecord() {
    auto file_name = QFileDialog::getSaveFileName(this, "Export", "sniffer-export.csv", "CSV Files (*.csv);;All Files (*)");
    if (file_name.isEmpty()) return;

    QFile file(file_name);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Error", "Cannot open file for writing.");
        return;
    }

    QTextStream out(&file);

    // Export header.
    for (int column = 0; column < 5; ++column) { // Don't export content.
        QStandardItem *headerItem = data.horizontalHeaderItem(column);
        if (column > 0) out << ",";
        if (headerItem) out << headerItem->text();
    }
    out << "\n";

    for (int row = 0; row < filter_data.rowCount(); ++row) {
        for (int column = 0; column < 5; ++column) {
            QString val = filter_data.data(filter_data.index(row, column)).toString();
            if (column > 0) out << ",";
            out << val;
        }
        out << "\n";
    }

    file.close();
}

void MainWindow::packetHandler(const DatalinkPacket &packet) {
    int row = data.rowCount();
    data.insertRow(row);
    data.setData(data.index(row, PacketModel::Time), QString::fromStdString(packet.get_time()));
    data.setData(data.index(row, PacketModel::Source), QString::fromStdString(packet.get_source()));
    data.setData(data.index(row, PacketModel::Destination), QString::fromStdString(packet.get_destination()));
    data.setData(data.index(row, PacketModel::Protocol), QString::fromStdString(packet.get_protocol()));
    data.setData(data.index(row, PacketModel::Description), QString::fromStdString(packet.get_description()));

    // Build contents.
    PacketContent contents;
    const auto &std_contents = packet.get_contents();
    for (const auto &std_pair : std_contents) {
        auto &pair = contents.emplace_back();
        pair.first = QString::fromStdString(std_pair.first);
        pair.second = QString::fromStdString(std_pair.second);
    }
    data.setData(data.index(row, PacketModel::Content), QVariant::fromValue(contents));

    table_view.scrollToBottom();
}

void MainWindow::resizeEvent(QResizeEvent *event) {
    const QSize new_size = event->size();

    device_selector.setGeometry(10, 10, 320, 30);
    record_btn.setGeometry(330, 10, 60, 30);
    stop_btn.setGeometry(390, 10, 60, 30);
    clear_btn.setGeometry(new_size.width() - 70, 10, 60, 30);
    export_btn.setGeometry(new_size.width() - 130, 10, 60, 30);
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

void MainWindow::onTableSelected() {
    QModelIndexList selected_indexes = table_view.selectionModel()->selectedIndexes();

    if (!selected_indexes.isEmpty()) {
        int row = selected_indexes.first().row();
        auto data = filter_data.data(filter_data.index(row, PacketModel::Content)).value<PacketContent>();
        packet_detail.setData(data);
    }
}

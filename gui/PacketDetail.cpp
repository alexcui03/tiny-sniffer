#include "PacketDetail.hpp"

PacketDetail::PacketDetail(QWidget *parent)
    : QWidget(parent), splitter(this), protocol_list(&splitter), detail(&splitter)
{
    detail.setReadOnly(true);
    protocol_list.setMaximumWidth(100);

    connect(&protocol_list, &QListWidget::currentRowChanged, this, &PacketDetail::onItemSelected);
}

PacketDetail::~PacketDetail() {}

void PacketDetail::setData(const PacketContent &data) {
    this->data = data;

    protocol_list.clear();
    for (const auto &item : data) {
        protocol_list.addItem(item.first);
    }
}

void PacketDetail::onItemSelected(int new_row) {
    detail.clear();
    if (new_row >= 0 && new_row < data.size()) {
        detail.setText(data[new_row].second);
    }
}

void PacketDetail::resizeEvent(QResizeEvent *event) {
    const QSize new_size = event->size();

    splitter.setGeometry(0, 0, new_size.width(), new_size.height());
}

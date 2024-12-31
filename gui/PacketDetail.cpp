#include "PacketDetail.hpp"

#include <QFont>
#include <QScrollBar>
#include <QRegularExpression>
#include <QVector>
#include <QPair>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>

PacketDetail::PacketDetail(QWidget *parent)
    : QWidget(parent), splitter(this), right(this), show_text_hex(&right), export_btn(&right)
{
    splitter.addWidget(&protocol_list);
    splitter.addWidget(&detail);

    this->setMinimumHeight(160);
    detail.setReadOnly(true);
    protocol_list.setMaximumWidth(100);
    show_text_hex.setGeometry(0, 0, 80, 30);
    show_text_hex.setText("Show Text");
    export_btn.setGeometry(0, 30, 80, 30);
    export_btn.setText("Export");

    // Use monospace font.
    QFont font("monospace", detail.fontPointSize());
    font.setStyleHint(QFont::Monospace);
    detail.setFont(font);

    connect(&protocol_list, &QListWidget::currentRowChanged, this, &PacketDetail::onItemSelected);
    connect(&show_text_hex, &QPushButton::clicked, this, &PacketDetail::changeShowHex);
    connect(&export_btn, &QPushButton::clicked, this, &PacketDetail::exportData);
}

PacketDetail::~PacketDetail() {}

void PacketDetail::setData(const PacketContent &data) {
    this->data = data;

    protocol_list.clear();
    for (const auto &item : data) {
        protocol_list.addItem(item.first);
    }
}

int PacketDetail::from_hex(QChar ch) {
    int n = ch.unicode();
    if (n >= '0' && n <= '9') return n - '0';
    if (n >= 'a' && n <= 'f') return n - 'a' + 10;
    if (n >= 'A' && n <= 'F') return n - 'A' + 10;
    return -1;
}

QString PacketDetail::hex_to_text(const QString &str) {
    auto bytes_str = str.split(' ').join("");
    auto bytes = QByteArray::fromHex(bytes_str.toUtf8());
    auto result = QString::fromUtf8(bytes);
    return result;
}

QString PacketDetail::hex_replacement(const QString &str) {
    QRegularExpression re("[0-9A-Fa-f]{2}( [0-9A-Fa-f]{2})+");
    QRegularExpressionMatchIterator iter = re.globalMatch(str);
    if (iter.hasNext()) {
        QRegularExpressionMatch match = iter.next();
        QString hex = str.mid(match.capturedStart(0), match.capturedLength(0));
        QString text = hex_to_text(hex);
        QString result = str.mid(0, match.capturedStart(0)) + text +
            str.mid(match.capturedStart(0) + match.capturedLength(0));
        return result;
    }
    return str;
}

void PacketDetail::onItemSelected(int new_row) {
    current_row = new_row;
    detail.clear();
    if (new_row >= 0 && new_row < data.size()) {
        detail.setText(data[new_row].second);

        show_hex = !show_hex;
        this->changeShowHex();
    }
}

void PacketDetail::resizeEvent(QResizeEvent *event) {
    const QSize new_size = event->size();

    right.setGeometry(new_size.width() - 80, 0, 80, new_size.height());
    splitter.setGeometry(0, 0, new_size.width() - 80, new_size.height());
}

void PacketDetail::changeShowHex() {
    show_hex = !show_hex;

    if (show_hex) {
        show_text_hex.setText("Show Text");
        if (current_row >= 0) {
            detail.setText(data[current_row].second);
        }
    } else {
        show_text_hex.setText("Show Hex");

        if (current_row >= 0) {
            detail.setText(hex_replacement(data[current_row].second));
        }
    }
}

void PacketDetail::exportData() {
    auto file_name = QFileDialog::getSaveFileName(this, "Export Packet", "sniffer-packet.txt", "Text Files (*.txt);;All Files (*)");
    if (file_name.isEmpty()) return;

    QFile file(file_name);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Error", "Cannot open file for writing.");
        return;
    }

    QTextStream out(&file);
    for (const auto &item : data) {
        out << "==========" << item.first << " (HEX)==========\n" << item.second << "\n";
    }
    for (const auto &item : data) {
        out << "==========" << item.first << " (TXT)==========\n" << hex_replacement(item.second) << "\n";
    }

    file.close();
}

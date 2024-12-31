#pragma once

#include <QWidget>
#include <QListWidget>
#include <QTextEdit>
#include <QSplitter>
#include <QPushButton>
#include <QResizeEvent>
#include <QString>

#include "utils.hpp"

class PacketDetail: public QWidget {
    Q_OBJECT
public:
    PacketDetail(QWidget *parent = nullptr);
    ~PacketDetail();
    void setData(const PacketContent &data);
    static QString hex_to_text(const QString &str);
    static int from_hex(QChar ch);
public slots:
    void onItemSelected(int new_row);
    void changeShowHex();
protected:
    void resizeEvent(QResizeEvent *event) override;
protected:
    QSplitter splitter;
    QWidget right;
    QListWidget protocol_list;
    QPushButton show_text_hex;
    QTextEdit detail;

    bool show_hex = true;
    int current_row = -1;
    PacketContent data;
};

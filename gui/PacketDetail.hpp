#pragma once

#include <QWidget>
#include <QListWidget>
#include <QTextEdit>
#include <QSplitter>
#include <QResizeEvent>

#include "utils.hpp"

class PacketDetail: public QWidget {
    Q_OBJECT
public:
    PacketDetail(QWidget *parent = nullptr);
    ~PacketDetail();
    void setData(const PacketContent &data);
public slots:
    void onItemSelected(int new_row);
protected:
    void resizeEvent(QResizeEvent *event) override;
protected:
    QSplitter splitter;
    QListWidget protocol_list;
    QTextEdit detail;

    PacketContent data;
};

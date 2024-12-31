#pragma once

#include <QVector>
#include <QPair>
#include <QString>
#include <QMetaType>

enum PacketModel {
    Time, Source, Destination, Protocol, Description, Content
};

using PacketContent = QVector<QPair<QString, QString>>;
Q_DECLARE_METATYPE(PacketContent);

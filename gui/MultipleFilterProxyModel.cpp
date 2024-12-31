#include "MultipleFilterProxyModel.hpp"

#include <QMap>
#include <QRegularExpression>
#include <QString>

#include "MainWindow.hpp"

MultipleFilterProxyModel::MultipleFilterProxyModel(QObject *parent): QSortFilterProxyModel(parent) {}

bool MultipleFilterProxyModel::setFilterPatten(const QString &filter) {
    src_ip_filter = dst_ip_filter = "";
    src_port_filter = dst_port_filter = protocol_filter = "";

    if (filter.trimmed().length() == 0) {
        this->invalidateFilter();
        return true;
    }

    QStringList items = filter.split(',');
    QMap<QString, QString> patterns;
    for (const QString &pattern : items) {
        if (!pattern.contains(':')) {
            return false;
        }

        QString k = pattern.section(':', 0, 0).trimmed();
        QString v = pattern.section(':', 1, -1).trimmed();
        patterns[k] = v;
    }

    // Build regex and match items.
    for (const auto &key : patterns.keys()) {
        const auto &value = patterns[key];

        if (key == "src-ip") {
            src_ip_filter = value.toUpper();
            src_ip_filter.replace(".", "\\.");
            src_ip_filter.replace("*", "[0-9A-Fa-f]*");
        } else if (key == "dst-ip") {
            dst_ip_filter = value.toUpper();
            dst_ip_filter.replace(".", "\\.");
            dst_ip_filter.replace("*", "[0-9A-Fa-f]*");
        } else if (key == "src-port") {
            src_port_filter = value;
        } else if (key == "dst-port") {
            dst_port_filter = value;
        } else if (key == "protocol") {
            protocol_filter = value.toUpper();
        }
    }

    this->invalidateFilter();

    return true;
}

bool MultipleFilterProxyModel::filterAcceptsRow(int source_row, const QModelIndex &source_parent) const {
    QAbstractItemModel *sourceModel = this->sourceModel();

    QModelIndex source_index = sourceModel->index(source_row, PacketModel::Source, source_parent);
    QModelIndex destination_index = sourceModel->index(source_row, PacketModel::Destination, source_parent);
    QModelIndex protocol_index = sourceModel->index(source_row, PacketModel::Protocol, source_parent);

    bool result = true;

    const QString &source = sourceModel->data(source_index).toString();
    if (src_ip_filter.length() > 0) {
        QRegularExpression re(src_ip_filter);
        if (src_port_filter.length() > 0) {
            re = QRegularExpression("\\[?" + src_ip_filter + "\\]?:" + src_port_filter);
        }
        result = result && re.match(source).hasMatch();
        if (!result) return result;
    }

    const QString &destination = sourceModel->data(destination_index).toString();
    if (dst_ip_filter.length() > 0) {
        QRegularExpression re(dst_ip_filter);
        if (dst_port_filter.length() > 0) {
            re = QRegularExpression("\\[?" + dst_ip_filter + "\\]?:" + dst_port_filter);
        }
        result = result && re.match(destination).hasMatch();
        if (!result) return result;
    }

    const QString &protocol = sourceModel->data(protocol_index).toString();
    if (protocol_filter.length() > 0) {
        result = result && protocol == protocol_filter;
        if (!result) return result;
    }

    return result;
}

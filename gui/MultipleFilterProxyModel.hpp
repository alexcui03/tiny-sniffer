#pragma once

#include <QSortFilterProxyModel>

class MultipleFilterProxyModel: public QSortFilterProxyModel {
    Q_OBJECT
public:
    MultipleFilterProxyModel(QObject *parent = nullptr);
    bool setFilterPatten(const QString &filter);
protected:
    bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override;
private:
    QString src_ip_filter;
    QString dst_ip_filter;
    QString src_port_filter;
    QString dst_port_filter;
    QString protocol_filter;
};

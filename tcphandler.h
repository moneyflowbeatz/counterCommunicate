#ifndef TCPHANDLER_H
#define TCPHANDLER_H

#include <QObject>
#include <QTcpSocket>
#include <vector>

class TcpHandler : public QObject {
    Q_OBJECT

public:
    explicit TcpHandler(const QString &hostName, int port, QObject *parent = nullptr);
    bool connectToServer();
    void disconnectFromServer();
    bool sendPacket(const std::vector<uint8_t> &packet);
    std::vector<uint8_t> receivePacket(int timeout);

private:
    QTcpSocket socket;
    QString hostName;
    int port;
};

#endif // TCPHANDLER_H

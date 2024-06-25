#include "tcphandler.h"
#include <QDebug>

TcpHandler::TcpHandler(const QString &hostName, int port, QObject *parent)
    : QObject(parent), hostName(hostName), port(port) {}

bool TcpHandler::connectToServer() {
    socket.connectToHost(hostName, port);
    return socket.waitForConnected(3000); // wait for 3 seconds to connect
}

void TcpHandler::disconnectFromServer() {
    if (socket.state() == QAbstractSocket::ConnectedState || socket.state() == QAbstractSocket::ConnectingState) {
        socket.disconnectFromHost();
        if (socket.state() == QAbstractSocket::UnconnectedState || socket.waitForDisconnected(3000)) {
            qDebug() << "\nDisconnected from server.";
        } else {
            qDebug() << "Failed to disconnect from server.";
        }
    } else {
        qDebug() << "Socket is already in UnconnectedState.";
    }
}

bool TcpHandler::sendPacket(const std::vector<uint8_t> &packet) {
    if (socket.state() == QAbstractSocket::ConnectedState) {
        socket.write(reinterpret_cast<const char*>(packet.data()), packet.size());
        return socket.waitForBytesWritten(3000); // wait for 3 seconds to write data
    }
    return false;
}

std::vector<uint8_t> TcpHandler::receivePacket(int timeout) {
    std::vector<uint8_t> data;
    if (socket.state() == QAbstractSocket::ConnectedState) {
        if (socket.waitForReadyRead(timeout)) {
            QByteArray byteArray = socket.readAll();
            data.assign(byteArray.begin(), byteArray.end());
        }
    }
    return data;
}

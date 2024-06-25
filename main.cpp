#include <QCoreApplication>
#include "tcphandler.h"
#include <QDebug>
#include <vector>
#include <iostream>
#include <iomanip>
#include <libpq-fe.h>

std::vector<uint8_t> constructPacket(const std::vector<uint8_t> &data, uint8_t command, uint16_t destAddress, uint16_t srcAddress);
uint8_t calculateCRC8(const std::vector<uint8_t> &data);
void ByteStuffing(std::vector<uint8_t> &data);

bool sendAndReceive(TcpHandler &tcpHandler, uint8_t command, std::vector<uint8_t> &response);
void ping(TcpHandler &tcpHandler);
void readFactoryString(TcpHandler &tcpHandler);
void readParameters(TcpHandler &tcpHandler);
void readInstantValues(TcpHandler &tcpHandler);

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);

    TcpHandler tcpHandler("213.222.245.173", 61189);
    if (!tcpHandler.connectToServer()) {
        qDebug() << "Failed to connect to server.";
        return -1;
    }

    ping(tcpHandler);
    readFactoryString(tcpHandler);
    readParameters(tcpHandler);
    readInstantValues(tcpHandler);

    tcpHandler.disconnectFromServer();

    return a.exec();
}

bool sendAndReceive(TcpHandler& tcpHandler, uint8_t command, std::vector<uint8_t>& response) {
    uint16_t destAddress = 0xFFF0;
    std::vector<uint16_t> srcAddresses = {0xD722, 0x12D7, 0x60EA};
    std::vector<uint8_t> packet;

    for (uint16_t srcAddress : srcAddresses) {
        if (command == 0x01) {
            std::vector<uint8_t> data = {};
            packet = constructPacket(data, command, destAddress, srcAddress);
        } else if (command == 0x0A) {
            std::vector<uint8_t> data = {0x02};
            packet = constructPacket(data, command, destAddress, srcAddress);
        } else if (command == 0x37) {
            std::vector<uint8_t> data = {0x00};
            packet = constructPacket(data, command, destAddress, srcAddress);
        }
        else {
            std::vector<uint8_t> data = {0x00};
            packet = constructPacket(data, command, destAddress, srcAddress);
        }


        if (!tcpHandler.sendPacket(packet)) {
            qDebug() << "Failed to send packet for command" << command << " with source address " << QString::number(srcAddress, 16).rightJustified(4, '0').toUpper();
            continue;
        }

        response = tcpHandler.receivePacket(1000);
        if (!response.empty()) {
            return true;
        } else {
            qDebug() << "Failed to receive response for command" << command << " with source address " << QString::number(srcAddress, 16).rightJustified(4, '0').toUpper();
        }
    }

    return false;
}

void ping(TcpHandler &tcpHandler) {
    std::vector<uint8_t> response;
    if (sendAndReceive(tcpHandler, 0x01, response)) {
        std::cout << "Ping response received: ";
        for (uint8_t byte : response) {
            std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << (int)byte << " ";
        }
        std::cout << "\n============================================" << std::endl << std::endl;

        if (response.size() >= 4 && response[0] == 0x73 && response.back() == 0x55) {
            std::vector<uint8_t> frame(response.begin() + 2, response.end() - 1);

            if (frame.size() >= 4) {
                uint8_t main_fw_version_low = frame[11];
                uint8_t additional_info = frame[12];
                uint16_t device_address = frame[13] | (frame[14] << 8);

                uint8_t main_fw_version_high = additional_info & 0x0F;
                uint8_t group_number = (additional_info >> 4) & 0x0F;

                std::cout << "Parsed Ping Response" << std::endl;
                std::cout << "Main Firmware Version: "
                          << static_cast<int>(main_fw_version_high) << "."
                          << static_cast<int>(main_fw_version_low) << std::endl;
                std::cout << "Group Number: " << static_cast<int>(group_number) << std::endl;
                std::cout << "Device Address: " << std::hex << std::uppercase << static_cast<int>(device_address) << std::endl;
                std::cout << "\n============================================" << std::endl << std::endl;
            } else {
                std::cout << "Invalid frame format." << std::endl;
            }
        } else {
            std::cout << "Invalid response format." << std::endl;
        }
    } else {
        std::cout << "Failed to receive ping response." << std::endl;
    }
}

void readFactoryString(TcpHandler &tcpHandler) {
    std::vector<uint8_t> response;
    if (sendAndReceive(tcpHandler, 0x0A, response)) {
        std::cout << "ReadFactoryString response received: ";
        for (uint8_t byte : response) {
            std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << (int)byte << " ";
        }
        std::cout << "\n============================================" << std::endl << std::endl;

        if (response.size() >= 33 && response[0] == 0x73 && response[1] == 0x55 && response.back() == 0x55) {
            std::vector<uint8_t> frame(response.begin() + 11, response.end() - 1);
            std::string asciiString(frame.begin() + 1, frame.end());

            std::cout << "Parsed ReadFactoryString Response" << std::endl;
            std::cout << "Value: " << asciiString << std::endl;
            std::cout << "\n============================================" << std::endl << std::endl;


        } else {
            std::cout << "Invalid response format." << std::endl;
        }

    } else {
        std::cout << "Failed to receive ReadFactoryString response." << std::endl;
    }
}

void readParameters(TcpHandler &tcpHandler) {
    std::vector<uint8_t> response;
    if (sendAndReceive(tcpHandler, 0x37, response)) {
        std::cout << "ReadParameters response received: ";
        for (uint8_t byte : response) {
            std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << (int)byte << " ";
        }
        std::cout << "\n============================================" << std::endl << std::endl;

        if (response.size() >= 3 && response[0] == 0x73 && response.back() == 0x55) {
            std::vector<uint8_t> frame(response.begin() + 13, response.end() - 1);

            if (frame.size() >= 3) {
                uint8_t parameterType = frame[0];
                uint16_t parameterValue = frame[1] | (frame[2] << 8);

                std::cout << "Parameter Type: 0x" << std::hex << std::uppercase << (int)parameterType << std::endl;
                std::cout << "Parameter Value: " << std::dec << parameterValue << std::endl;
                std::cout << "\n============================================" << std::endl << std::endl;
        } else {
            std::cout << "Invalid response format." << std::endl;
        }
    }
    } else {
        std::cout << "Failed to receive ReadParameters response." << std::endl;
    }
}

void readInstantValues(TcpHandler &tcpHandler) {
    std::vector<uint8_t> response;
    if (sendAndReceive(tcpHandler, 0x2B, response)) {
        std::cout << "ReadInstantValues response received: ";
        for (uint8_t byte : response) {
            std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << (int)byte << " ";
        }
        std::cout << "\n============================================" << std::endl << std::endl;

        if (response.size() >= 28 && response[0] == 0x73 && response.back() == 0x55) {
            std::vector<uint8_t> frame(response.begin() + 13, response.end() - 1);

            if (frame.size() >= 28) {
                uint8_t numGroup = frame[0];
                uint16_t kofTranNa = frame[1] | (frame[2] << 8);
                uint16_t kofTranTok = frame[3] | (frame[4] << 8);
                uint16_t actEng = frame[5] | (frame[6] << 8);
                uint16_t reactEng = frame[7] | (frame[8] << 8);
                uint16_t frequency = frame[9] | (frame[10] << 8);
                uint16_t COSf = frame[11] | (frame[12] << 8);
                uint16_t volA = frame[13] | (frame[14] << 8);
                uint16_t volB = frame[15] | (frame[16] << 8);
                uint16_t volC = frame[17] | (frame[18] << 8);
                uint32_t currA = frame[19] | (frame[20] << 8) | (frame[21] << 16);
                uint32_t currB = frame[22] | (frame[23] << 8) | (frame[24] << 16);
                uint32_t currC = frame[25] | (frame[26] << 8) | (frame[27] << 16);

                std::cout << "Group number: " << std::dec << (int)numGroup << std::endl;
                std::cout << "Transformation Coefficient Voltage: " << kofTranNa << std::endl;
                std::cout << "Transformation Coefficient Current: " << kofTranTok << std::endl;
                std::cout << "Active Energy: " << actEng / 1000.0 << " kW" << std::endl;
                std::cout << "Reactive Energy: " << reactEng / 1000.0 << " kVAR" << std::endl;
                std::cout << "Frequency: " << frequency / 100.0 << " Hz" << std::endl;
                std::cout << "COSf: " << COSf / 1000.0 << std::endl;
                std::cout << "Voltage Phase A: " << volA / 100.0 << " V" << std::endl;
                std::cout << "Voltage Phase B: " << volB / 100.0 << " V" << std::endl;
                std::cout << "Voltage Phase C: " << volC / 100.0 << " V" << std::endl;
                std::cout << "Current Phase A: " << currA / 1000.0 << " A" << std::endl;
                std::cout << "Current Phase B: " << currB / 1000.0 << " A" << std::endl;
                std::cout << "Current Phase C: " << currC / 1000.0 << " A" << std::endl;
                std::cout << "\n============================================" << std::endl << std::endl;


                PGconn *conn = PQconnectdb("host=localhost port=5432 dbname=uspd user=postgres password=1234567890");
                if (PQstatus(conn) != CONNECTION_OK) {
                    std::cerr << "Connection to database failed: " << PQerrorMessage(conn) << std::endl;
                    PQfinish(conn);
                    return;
                } else {
                    std::cout << "Connected to database!" << std::endl;
                }

                PGresult *res_before = PQexec(conn, "SELECT * FROM instant_one_phase WHERE id = 2");
                if (PQresultStatus(res_before) != PGRES_TUPLES_OK) {
                    std::cerr << "Select before update failed: " << PQerrorMessage(conn) << std::endl;
                    PQclear(res_before);
                    PQfinish(conn);
                    return;
                } else {
                    std::cout << "Values before update:" << std::endl;
                    int nFields = PQnfields(res_before);
                    for (int i = 0; i < nFields; i++) {
                        std::cout << PQfname(res_before, i) << ": " << PQgetvalue(res_before, 0, i) << std::endl;
                    }
                    PQclear(res_before);
                }

                const char *sql = "UPDATE instant_one_phase SET volt_trans_ratio = $1, curr_trans_ratio = $2, active_power = $3, reactive_power = $4, full_power = $5, frequency = $6, cos = $7, volt_a = $8, volt_b = $9, volt_c = $10, curr_a_phase_current = $11, curr_b_null_current = $12, curr_c_current_diff = $13, read_time = current_timestamp WHERE id = 2";
                const char *paramValues[13];
                int paramLengths[13];
                int paramFormats[13] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

                std::string param1 = std::to_string(kofTranNa);
                std::string param2 = std::to_string(kofTranTok);
                std::string param3 = std::to_string(actEng);
                std::string param4 = std::to_string(reactEng);
                std::string param5 = std::to_string(actEng + reactEng);
                std::string param6 = std::to_string(frequency);
                std::string param7 = std::to_string(COSf);
                std::string param8 = std::to_string(volA);
                std::string param9 = std::to_string(volB);
                std::string param10 = std::to_string(volC);
                std::string param11 = std::to_string(currA);
                std::string param12 = std::to_string(currB);
                std::string param13 = std::to_string(currC);

                paramValues[0] = param1.c_str();
                paramValues[1] = param2.c_str();
                paramValues[2] = param3.c_str();
                paramValues[3] = param4.c_str();
                paramValues[4] = param5.c_str();
                paramValues[5] = param6.c_str();
                paramValues[6] = param7.c_str();
                paramValues[7] = param8.c_str();
                paramValues[8] = param9.c_str();
                paramValues[9] = param10.c_str();
                paramValues[10] = param11.c_str();
                paramValues[11] = param12.c_str();
                paramValues[12] = param13.c_str();

                PGresult *res = PQexecParams(conn, sql, 13, NULL, paramValues, paramLengths, paramFormats, 0);

                if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                    std::cerr << "Failed to execute SQL statement: " << PQerrorMessage(conn) << std::endl;
                    PQclear(res);
                    PQfinish(conn);
                    return;
                }

                PQclear(res);

                PGresult *res_after = PQexec(conn, "SELECT * FROM instant_one_phase WHERE id = 2");
                if (PQresultStatus(res_after) != PGRES_TUPLES_OK) {
                    std::cerr << "Select after update failed: " << PQerrorMessage(conn) << std::endl;
                    PQclear(res_after);
                    PQfinish(conn);
                    return;
                } else {
                    std::cout << "\nValues after update:" << std::endl;
                    int nFields = PQnfields(res_after);
                    for (int i = 0; i < nFields; i++) {
                        std::cout << PQfname(res_after, i) << ": " << PQgetvalue(res_after, 0, i) << std::endl;
                    }
                    PQclear(res_after);
                }

                PQfinish(conn);
            } else {
                std::cout << "Invalid response format." << std::endl;
            }
        } else {
            std::cout << "Invalid response format." << std::endl;
        }
    } else {
        std::cout << "Failed to receive ReadInstantValues response." << std::endl;
    }
}

std::vector<uint8_t> constructPacket(const std::vector<uint8_t>& data, uint8_t command, uint16_t destAddress, uint16_t srcAddress) {
    std::vector<uint8_t> packet;

    packet.push_back(0x73);
    packet.push_back(0x55);
    uint8_t paramLen = (data.size() & 0x1F);
    paramLen |= (1 << 5);
    packet.push_back(paramLen);
    packet.push_back(0x00);



    packet.push_back(srcAddress & 0xFF);
    packet.push_back((srcAddress >> 8) & 0xFF);
    packet.push_back(destAddress & 0xFF);
    packet.push_back((destAddress >> 8) & 0xFF);


    packet.push_back(command);

    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);

    packet.insert(packet.end(), data.begin(), data.end());

    uint8_t crc = calculateCRC8(std::vector<uint8_t>(packet.begin() + 2, packet.end()));
    packet.push_back(crc);


    std::vector<uint8_t> stuffingPart(packet.begin() + 2, packet.end());
    ByteStuffing(stuffingPart);

    std::vector<uint8_t> stuffedPacket(packet.begin(), packet.begin() + 2);
    stuffedPacket.insert(stuffedPacket.end(), stuffingPart.begin(), stuffingPart.end());
    stuffedPacket.push_back(0x55);

    std::cout << "Constructed packet:";
    for (uint8_t byte : stuffedPacket) {
        std::cout << " 0x" << std::hex << std::uppercase << (int)byte;
    }
    std::cout << std::endl;
    return stuffedPacket;
}

uint8_t calculateCRC8(const std::vector<uint8_t> &data) {
    uint8_t crc = 0x00;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; ++i) {
            if (crc & 0x80) {
                crc = (crc << 1) ^ 0xA9;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

void ByteStuffing(std::vector<uint8_t>& data) {
    for (auto it = data.begin(); it != data.end(); ++it) {
        if (*it == 0x55) {
            *it = 0x73;
            it = data.insert(it + 1, 0x11);
        } else if (*it == 0x73) {
            it = data.insert(it + 1, 0x22);
        }
    }
}

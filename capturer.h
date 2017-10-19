#ifndef CAPTURER_H
#define CAPTURER_H

#include <QThread>
#include <pcap.h>
#include <QDebug>
#include <QTimer>


class Capturer : public QThread
{
    Q_OBJECT
public:
    Capturer();
    ~Capturer();
    QStringList getDevicesList();
    bool openDevice(int index);
protected:
    void run();
private:
    pcap_t *adhandle;
    static QString packetBuffer;
    static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);    
    QTimer timer;
private slots:
    void emitDataSignal();
signals:
    void readyRead(QString);
};

#endif // CAPTURER_H

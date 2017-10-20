#include "capturer.h"
#include "packetstruct.h"

#pragma comment(lib,"C:/WpdPack/Lib/x64/wpcap.lib")
#pragma comment(lib,"C:/WpdPack/Lib/x64/Packet.lib")
#pragma comment(lib,"wsock32")

QString Capturer::packetBuffer;

Capturer::Capturer() : adhandle(NULL)
{
    connect(&timer, SIGNAL(timeout()), this, SLOT(emitDataSignal()));

}

Capturer::~Capturer()
{
    if (adhandle != NULL)
    {
        pcap_breakloop(adhandle);
        pcap_close(adhandle);
    }
    wait();
}

QStringList Capturer::getDevicesList()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    QStringList devList;
    QString ip;
    pcap_addr_t *a;

    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        qDebug() << errbuf;
    }

    for(d = alldevs; d; d = d->next)
    {
        for(a=d->addresses;a;a=a->next)
        {
            if (a->addr->sa_family == AF_INET)
            {
                ip = inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr);
            }
        }
        devList << QString(d->description) + "(" + ip + ")";
    }

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    return devList;


}

bool Capturer::openDevice(int index)
{   
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;

    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        qDebug() << errbuf;
    }

    for(d = alldevs; d; d = d->next)
    {
        if (i == index)
        {
            break;
        }
        i++;
    }


    /* Open the device */
    if ( (adhandle= pcap_open(d->name,          // name of the device
                              65536,            // portion of the packet to capture
                              // 65536 guarantees that the whole packet will be captured on all the link layers
                              PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                              1000,             // read timeout
                              NULL,             // authentication on the remote machine
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        printLog("设备打开错误！");
        return false;
    }

    printLog("设备已打开！");

    if (adhandle != NULL)
    {
        start();
    }

    timer.start(100);

    pcap_freealldevs(alldevs);

    return true;

}

void Capturer::run()
{
    if (adhandle != NULL)
        pcap_loop(adhandle, 0, packet_handler, NULL);
}

void Capturer::packet_handler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data)
{

    (VOID)(param);
    (VOID)(header);

    ether_header * eheader = (ether_header*)pkt_data;

    //ARP
    if (eheader->ether_type == htons(ETH_ARP))
    {
        char buffer[100];
        ArpPacket *recv = (ArpPacket *) pkt_data;
        if (*(unsigned short *) (pkt_data + 20) == htons(ARP_REPLY))
        {
            sprintf(buffer, "[ARP] IP:%d.%d.%d.%d MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
                    recv->ah.SourceIpAdd & 255,
                    recv->ah.SourceIpAdd >> 8 & 255,
                    recv->ah.SourceIpAdd >> 16 & 255,
                    recv->ah.SourceIpAdd >> 24 & 255,
                    recv->ed.SourMAC[0],
                    recv->ed.SourMAC[1],
                    recv->ed.SourMAC[2],
                    recv->ed.SourMAC[3],
                    recv->ed.SourMAC[4],
                    recv->ed.SourMAC[5]);
            packetBuffer.append(buffer);
        }
    }
    //IP
    if(eheader->ether_type == htons(ETHERTYPE_IP))
    {
        ip_header * ih = (ip_header*)(pkt_data+14); /* get ip header */
        if(ih->proto == htons(TCP_PROTOCAL))
        {
            int ip_len = ntohs(ih->tlen); /* get ip length, it contains header and body */

            int find_http = false;
            char* ip_pkt_data = (char*)ih;           
            int n = 0;
            char buffer[BUFFER_MAX_LENGTH];
            int bufsize = 0;

            for(; n<ip_len; n++)
            {
                /* http get or post request */
                if(!find_http && ((n+3<ip_len && strncmp(ip_pkt_data+n,"GET",strlen("GET")) ==0 )
                                  || (n+4<ip_len && strncmp(ip_pkt_data+n,"POST",strlen("POST")) == 0)) )
                    find_http = true;

                /* http response */
                if(!find_http && n+8<ip_len && strncmp(ip_pkt_data+n,"HTTP/1.1",strlen("HTTP/1.1"))==0)
                    find_http = true;

                /* if http is found */
                if(find_http)
                {
                    buffer[bufsize] = ip_pkt_data[n]; /* copy http data to buffer */
                    bufsize ++;
                }
            }
            /* print http content */
            if(find_http)
            {
                buffer[bufsize] = '\0';
                packetBuffer.append(buffer);

            }
        }

    }

}

void Capturer::printLog(QString str)
{
    emit log(str);
}

void Capturer::emitDataSignal()
{
    if (packetBuffer.size() > 0)
    {
        emit readyRead(packetBuffer);
        packetBuffer.clear();
    }
}

#include "capturer.h"
#include "packetstruct.h"

#pragma comment(lib,"C:/WpdPack/Lib/x64/wpcap.lib")
#pragma comment(lib,"C:/WpdPack/Lib/x64/Packet.lib")
#pragma comment(lib,"wsock32")

QString Capturer::packetBuffer;

/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

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

bool Capturer::sendArpReq(QString ip)
{
    unsigned char sendbuf[42]; //arp包结构大小
    EthernetHeader eh;
    Arpheader ah;

    quint8 mac[6] = {0x00, 0x16, 0x3E, 0x08, 0xA6, 0x4D};
    //赋值MAC地址
    memset(eh.DestMAC, 0xff, 6);       //目的地址为全为广播地址
    memcpy(eh.SourMAC, mac, 6);
    memcpy(ah.SourceMacAdd, mac, 6);
    memset(ah.DestMacAdd, 0x00, 6);
    eh.EthType = htons(ETH_ARP);
    ah.HardwareType = htons(ARP_HARDWARE);
    ah.ProtocolType = htons(ETH_IP);
    ah.HardwareAddLen = 6;
    ah.ProtocolAddLen = 4;
    ah.SourceIpAdd = inet_addr(ip.toLocal8Bit().data()); //请求方的IP地址为自身的IP地址
    ah.OperationField = htons(ARP_REQUEST);
    //向局域网内广播发送arp包
    unsigned long myip = inet_addr(ip.toLocal8Bit().data());
    unsigned long mynetmask = inet_addr(netmask);
    unsigned long hisip = htonl((myip & mynetmask));
    //向255个主机发送
    for (int i = 0; i < HOSTNUM; i++) {
        ah.DestIpAdd = htonl(hisip + i);
        //构造一个ARP请求
        memset(sendbuf, 0, sizeof(sendbuf));
        memcpy(sendbuf, &eh, sizeof(eh));
        memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
        //如果发送成功
        if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
            //printf("\nPacketSend succeed\n");
        } else {
            printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
        }
        Sleep(50);
    }
    Sleep(1000);
    flag = TRUE;
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

void Capturer::ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask)
{
    pcap_addr_t *a;
    //遍历所有的地址,a代表一个pcap_addr
    for (a = d->addresses; a; a = a->next) {
        switch (a->addr->sa_family) {
        case AF_INET:  //sa_family ：是2字节的地址家族，一般都是“AF_xxx”的形式。通常用的都是AF_INET。代表IPV4
            if (a->addr) {
                char *ipstr;
                //将地址转化为字符串
                ipstr = iptos(((struct sockaddr_in *) a->addr)->sin_addr.s_addr); //*ip_addr
                printf("ipstr:%s\n",ipstr);
                memcpy(ip_addr, ipstr, 16);
            }
            if (a->netmask) {
                char *netmaskstr;
                netmaskstr = iptos(((struct sockaddr_in *) a->netmask)->sin_addr.s_addr);
                printf("netmask:%s\n",netmaskstr);
                memcpy(ip_netmask, netmaskstr, 16);
            }
        case AF_INET6:
            break;
        }
    }
}

int Capturer::GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac)
{
    unsigned char sendbuf[42]; //arp包结构大小
    int i = -1;
    int res;
    EthernetHeader eh; //以太网帧头
    Arpheader ah;  //ARP帧头
    struct pcap_pkthdr * pkt_header;
    const u_char * pkt_data;
    //将已开辟内存空间 eh.dest_mac_add 的首 6个字节的值设为值 0xff。
    memset(eh.DestMAC, 0xff, 6); //目的地址为全为广播地址
    memset(eh.SourMAC, 0x0f, 6);
    memset(ah.DestMacAdd, 0x0f, 6);
    memset(ah.SourceMacAdd, 0x00, 6);
    //htons将一个无符号短整型的主机数值转换为网络字节顺序
    eh.EthType = htons(ETH_ARP);
    ah.HardwareType= htons(ARP_HARDWARE);
    ah.ProtocolType = htons(ETH_IP);
    ah.HardwareAddLen = 6;
    ah.ProtocolAddLen = 4;
    ah.SourceIpAdd = inet_addr("100.100.100.100"); //随便设的请求方ip
    ah.OperationField = htons(ARP_REQUEST);
    ah.DestIpAdd = inet_addr(ip_addr);
    memset(sendbuf, 0, sizeof(sendbuf));
    memcpy(sendbuf, &eh, sizeof(eh));
    memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
    printf("%s",sendbuf);
    if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
        printf("\nPacketSend succeed\n");
    } else {
        printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
        return 0;
    }
    //从interface或离线记录文件获取一个报文
    //pcap_next_ex(pcap_t* p,struct pcap_pkthdr** pkt_header,const u_char** pkt_data)
    while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
        if (*(unsigned short *) (pkt_data + 12) == htons(ETH_ARP)
                && *(unsigned short*) (pkt_data + 20) == htons(ARP_REPLY)
                && *(unsigned long*) (pkt_data + 38)
                == inet_addr("100.100.100.100")) {
            for (i = 0; i < 6; i++) {
                ip_mac[i] = *(unsigned char *) (pkt_data + 22 + i);
            }
            printf("获取自己主机的MAC地址成功!\n");
            break;
        }
    }
    if (i == 6) {
        return 1;
    } else {
        return 0;
    }
}

void Capturer::emitDataSignal()
{
    if (packetBuffer.size() > 0)
    {
        emit readyRead(packetBuffer);
        packetBuffer.clear();
    }
}

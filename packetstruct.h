#ifndef PACKETSTRUCT_H
#define PACKETSTRUCT_H

#include <QString>

#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1   //ARP请求
#define ARP_REPLY       2      //ARP应答
#define HOSTNUM         255   //主机数量
#define ETHERTYPE_IP 0x0800 /* ip protocol */
#define TCP_PROTOCAL 0x0600 /* tcp protocol */
#define BUFFER_MAX_LENGTH 65536 /* buffer max length */

#pragma pack(1)

typedef struct ether_header {
    u_char ether_shost[6]; /* source ethernet address, 8 bytes */
    u_char ether_dhost[6]; /* destination ethernet addresss, 8 bytes */
    u_short ether_type;                 /* ethernet type, 16 bytes */
}ether_header;

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;



//帧头部结构体，共14字节
struct EthernetHeader
{
    u_char DestMAC[6];    //目的MAC地址 6字节
    u_char SourMAC[6];   //源MAC地址 6字节
    u_short EthType;         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

//28字节ARP帧结构
struct Arpheader {
    unsigned short HardwareType; //硬件类型
    unsigned short ProtocolType; //协议类型
    unsigned char HardwareAddLen; //硬件地址长度
    unsigned char ProtocolAddLen; //协议地址长度
    unsigned short OperationField; //操作字段
    unsigned char SourceMacAdd[6]; //源mac地址
    unsigned long SourceIpAdd; //源ip地址
    unsigned char DestMacAdd[6]; //目的mac地址
    unsigned long DestIpAdd; //目的ip地址
};

//arp包结构
struct ArpPacket {
    EthernetHeader ed;
    Arpheader ah;
};

#pragma pack()

typedef struct
{
    QString name;
    QString description;
    QString ip;
    QString mask;

}DeviceInfo;



#endif // PACKETSTRUCT_H

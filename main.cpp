#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <ifaddrs.h>

#include <arpa/inet.h>

#include <asm/types.h>

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>

#include <vector>
#include <string>
#include <map>
#include <regex>

extern "C" unsigned int if_nametoindex(const char *ifname);
extern "C" unsigned int if_indextoname(unsigned int ifindex, const char *ifname);

#define HW_ADDR_LENGTH 6
#define IPV4_ADDR_LENGTH 4

bool nomeflag = false;
unsigned char myinterfaceip[4]{0};
unsigned char mysubnetmask[4]{0};
unsigned char mti_binary[4]{0};
unsigned char nsi_binary[4]{0};
unsigned char ndi_binary[4]{0};
unsigned char nsp_binary[4]{0};
unsigned char ndp_binary[4]{0};

struct __attribute__((packed)) ARPHeader
{
    unsigned short HWType{0};
    unsigned short ProcType{0};
    unsigned char HWSize{0};
    unsigned char ProcSize{0};
    unsigned short Opcode{0};
    unsigned char SenderMAC[6]{0};
    unsigned char SenderIP[4]{0};
    unsigned char TargetMAC[6]{0};
    unsigned char TargetIP[4]{0};
};
struct __attribute__((packed)) IP4Header {
    unsigned char VerAndHeaderLength{0};
    unsigned char TypeOfService{0};
    unsigned short Length{0};
    unsigned short Ident{0};
    unsigned short Flag{0};
    unsigned char TTL{0};
    unsigned char Proto{0};
    unsigned short CheckSum{0};
    unsigned char SRCIP[4]{0};
    unsigned char DSTIP[4]{0};
    unsigned char OptAndData[1480]{0};
};
struct __attribute__((packed)) PseudoIP4Header {
    unsigned char SRCIP[4]{0};
    unsigned char DSTIP[4]{0};
    unsigned char DUMMY{0};
    unsigned char Proto{0};
    unsigned short Length{0};
};

struct __attribute__((packed)) MACHeader {
    unsigned char destMACAddr[6]{0};
    unsigned char srcMACAddr[6]{0};
    unsigned short upperType{0};
    ARPHeader arpHeader;
    //alignment
    unsigned char padding[18]{0};
};
struct __attribute__((packed)) MACIP4Header {
    unsigned char destMACAddr[6]{0};
    unsigned char srcMACAddr[6]{0};
    unsigned short upperType{0};
    IP4Header ip4Header;
    //alignment
    unsigned char padding[18]{0};
};

struct IPSock {
    int fdSock{0};
    explicit IPSock () {
    }

    ~IPSock () {
        if (0 != fdSock) {
            close(fdSock);
        }
    }

    IPSock& operator = (int iFdSock) {
        if (0 != fdSock) {
            close(fdSock);
        }

        fdSock = iFdSock;
        return *this;
    }

    bool operator == (int iVal) const {
        return (iVal == fdSock);
    }

};

IPSock ipSock;
IPSock ipSock_out;

bool enabledthepooling = false;
unsigned long timeofpooling;

bool nataddr4host = false;

unsigned char incdec_ttl{'\0'};

unsigned char ghxbuf[65536]{'\0'};
unsigned char ghzbuf[65536]{'\0'};
unsigned char ghybuf[sizeof(MACHeader)]{'\0'};
unsigned char buf_arpin[sizeof(MACHeader)]{'\0'};
unsigned char buf_arpout[sizeof(MACHeader)]{'\0'};

template <typename T>
bool isEmpty(const T p, int c) {
    for (int i = 0; i < c; i++) {
        if ('\0' != p[i]) return false;
    }

    return true;
}

void usage() {
    fprintf(stdout, "l3trans (based arpreply version 1.0), release date: 2025-12-29\n\n"
                    "Usage: l3trans --help | -list | [-i interfacename] [-itval n] -rti ipaddr -rqi ipaddr [-rqm macaddr] [-q]\n"
                    "-list           list all interfaces\n"
                    "-i              specify outgoing interface\n"
                    "-itval          specify the interval seconds between two sending (default: 1)\n"
                    "-nome           ignores this device packet\n"
                    "--help          display help\n"
                    "-rti            reply to ip address\n"
                    "-rqi            ip address that using to reply\n"
                    "-rqm            mac address that using to reply\n"
                    "-q              quite model\n"
                    "\n"
                    "example: l3trans -rti 192.168.1.123 -rqi 192.168.1.1 -rqm 00:00:00:00:00:00\n"
                    "just work in ipv4 networking, ipv6 is still considering\n"
                    "");
}

std::vector<std::string> getCmdOutput(const char *__command, const char *__modes = "r") {

    std::vector<std::string> result;
    FILE *fp;
    char path[1024];
    /* Open the command for reading. */
    fp = popen(__command, __modes);
    if (fp == NULL) {
        printf("Failed to run command\n" );
        return result;
    }


    /* Read the output a line at a time - output it. */
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
        result.push_back(std::string(path));
    }

    pclose(fp);
    return result;
}

unsigned char rti4searchmac[4];

//to do
std::string getARPReplyMAC(int fd, const char* interfacename, const char* ipaddr, unsigned char* macaddr) {
    //send arp request
    MACHeader arpReq;
    //construct arp request
    memset(arpReq.destMACAddr, 0xff, sizeof(arpReq.destMACAddr));
    memset(arpReq.arpHeader.TargetMAC, 0xff, sizeof(arpReq.arpHeader.TargetMAC));
    struct ifreq ifreq;
    memset(ifreq.ifr_name, '\0', sizeof(ifreq.ifr_name));
    strcpy(ifreq.ifr_name, interfacename);

    if (-1 == ioctl(fd, SIOCGIFHWADDR, &ifreq)) {
        perror("SIOCGIFHWADDR");
        exit(1);
    }

    for (int idx = 0; idx < HW_ADDR_LENGTH; idx++) {
        *(arpReq.srcMACAddr + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
        *(arpReq.arpHeader.SenderMAC + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
    }

    struct ifaddrs* ifaddrs{nullptr};
    if (-1 == getifaddrs(&ifaddrs) || nullptr == ifaddrs) {
        perror("getifaddrs");
        exit(1);
    }


    struct ifaddrs* oneifaddr = ifaddrs;
    while (nullptr != oneifaddr) {
        if (!memcmp(oneifaddr->ifa_name, interfacename, strlen(oneifaddr->ifa_name))) {
            struct sockaddr* ifa_addr = oneifaddr->ifa_addr;
            if (ifa_addr->sa_family == AF_INET) {
                void* tmpaddr = &((struct sockaddr_in*)ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN]{'\0'};
                inet_ntop(AF_INET, tmpaddr, addressBuffer, INET_ADDRSTRLEN);
                memcpy(arpReq.arpHeader.SenderIP,(void*)&((struct sockaddr_in *)ifa_addr)->sin_addr, IPV4_ADDR_LENGTH);
                break;
            }
        }
        oneifaddr = oneifaddr->ifa_next;
    }

    freeifaddrs(ifaddrs);

    if (isEmpty(arpReq.arpHeader.SenderIP, sizeof(arpReq.arpHeader.SenderIP))) {
        memcpy(arpReq.arpHeader.SenderIP,rti4searchmac,4);
    }
    if (isEmpty(arpReq.arpHeader.SenderIP, sizeof(arpReq.arpHeader.SenderIP))) {
        fprintf(stdout, "Can not to found %s's ipv4 addr", interfacename);
        exit(1);
    }

    arpReq.upperType = htons(0x0806);
    arpReq.arpHeader.HWType = htons(0x0001);
    arpReq.arpHeader.ProcType = htons(0x0800);
    arpReq.arpHeader.HWSize = 6;
    arpReq.arpHeader.ProcSize = 4;
    arpReq.arpHeader.Opcode = htons(0x0001);
    in_addr_t targetIP = inet_addr(ipaddr);
    memcpy(arpReq.arpHeader.TargetIP, (void*)(&targetIP), IPV4_ADDR_LENGTH);



    struct sockaddr_ll sockAddr;
    sockAddr.sll_family = AF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ARP);
    if (-1 == ioctl(fd, SIOCGIFINDEX, &ifreq)) {
        perror("SIOCGIFINDEX");
        exit(1);
    }

    sockAddr.sll_ifindex = ifreq.ifr_ifindex;
    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr.sll_pkttype = PACKET_BROADCAST;
    sockAddr.sll_halen = HW_ADDR_LENGTH;
    memset(sockAddr.sll_addr + HW_ADDR_LENGTH, '\0', 2);

    memcpy(sockAddr.sll_addr, arpReq.arpHeader.SenderIP, sizeof(arpReq.arpHeader.SenderIP));

    if (-1 == sendto(fd, (void*)(&arpReq), sizeof(arpReq), 0, (struct sockaddr *)(&sockAddr), sizeof(sockAddr))) {
        perror("sendto");
        exit(-1);
    }

    time_t awaittimetmp = time(NULL);

    unsigned char buf[60]{'\0'};
    for (;;) {
        struct sockaddr sockAddr;
        socklen_t len;
        if (-1 == recvfrom(fd, (void*)(&buf), sizeof(buf), 0, (struct sockaddr *)(&sockAddr), &len)) {
            perror("recvfrom");
            exit(-1);
        }

        MACHeader &arprep = (MACHeader &)buf;
        if (ntohs(arprep.upperType) == 0x0806 && ntohs(arprep.arpHeader.Opcode) == 0x0002) {

            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, (void*)(&arprep.arpHeader.SenderIP), addressBuffer, INET_ADDRSTRLEN);

            fprintf(stdout, "mac: %02x:%02x:%02x:%02x:%02x:%02x, ip: %s\n",
                    arprep.arpHeader.SenderMAC[0],
                    arprep.arpHeader.SenderMAC[1],
                    arprep.arpHeader.SenderMAC[2],
                    arprep.arpHeader.SenderMAC[3],
                    arprep.arpHeader.SenderMAC[4],
                    arprep.arpHeader.SenderMAC[5],
                    addressBuffer);
        }
        if ((arprep.arpHeader.SenderIP[0] == arpReq.arpHeader.TargetIP[0]) && (arprep.arpHeader.SenderIP[1] == arpReq.arpHeader.TargetIP[1]) && (arprep.arpHeader.SenderIP[2] == arpReq.arpHeader.TargetIP[2]) && (arprep.arpHeader.SenderIP[3] == arpReq.arpHeader.TargetIP[3])) {
            memcpy((void*)(macaddr), (void*)(&arprep.arpHeader.SenderMAC), 6);
            break;
        }
        if ((awaittimetmp+5) <= time(NULL)) {break;}
    }
    //receive arp response

    return std::string();
}

bool isInterfaceOnline(int fd, const char* interface) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, interface);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
    }
    return !!(ifr.ifr_flags | IFF_RUNNING);
}

void listInterfaces() {
    struct packet_mreq mreq;
    struct ifaddrs * ifAddrStruct{nullptr};
    struct ifaddrs * ifa{nullptr};
    void * tmpAddrPtr{nullptr};

    getifaddrs(&ifAddrStruct);

    IPSock ipSock;
    ipSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ipSock == -1) {
        perror("Fail to open socket");
        return;
    }

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            struct ifreq ifreq;
            strcpy(ifreq.ifr_name, ifa->ifa_name);
            if (-1 == ioctl(ipSock.fdSock, SIOCGIFHWADDR, &ifreq)) {
                perror("SIOCGIFHWADDR");
                exit(1);
            }
            if (-1 == ioctl(ipSock.fdSock, SIOCGIFINDEX, &ifreq)) {
            }
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = ifreq.ifr_ifindex;
    mreq.mr_alen = 0;
    mreq.mr_address[0] = '\0';
    if (setsockopt(ipSock.fdSock,SOL_PACKET,PACKET_ADD_MEMBERSHIP,(void*)&mreq,sizeof(mreq)) < 0){
    }

            if (!isInterfaceOnline(ipSock.fdSock, ifa->ifa_name)) {
                continue;
            }

            fprintf(stdout, "%s\t%s\t%02x-%02x-%02x-%02x-%02x-%02x\n", ifa->ifa_name, addressBuffer,
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[0]),
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[1]),
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[2]),
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[3]),
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[4]),
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[5]));
        } else if (ifa->ifa_addr->sa_family == AF_INET6) { // check it is IP6
#ifdef IPV6
            // is a valid IP6 Address
            tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
            printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);
#endif
        }
    }

    if (ifAddrStruct != NULL)
        freeifaddrs(ifAddrStruct);
}

struct PseudoIP4HeaderandIPX{
    PseudoIP4Header pseudoIP4Header;
    unsigned char Payload[65536-12]{0};
};

bool ishavepreviousheader_for_icmp=false;

void decipchecksum(IP4Header* pip4Header){
    unsigned int checksum = (~(htons(pip4Header->CheckSum))) & 0xFFFF;
    checksum -= htons((*(short*)((&pip4Header->VerAndHeaderLength) + (4 * 2))));
    if (((checksum >> 16) & 1)){checksum = ((checksum & 0xFFFF) - ((checksum >> 16) & 1)) & 0xFFFF;}
    for (int cnt=6;cnt<10;cnt++){
        checksum -= htons((*(short*)((&pip4Header->VerAndHeaderLength) + (cnt * 2))));
        if (((checksum >> 16) & 1)){checksum = ((checksum & 0xFFFF) - ((checksum >> 16) & 1)) & 0xFFFF;}
    }
    checksum = (~(htons((checksum & 0xFFFF) - ((checksum >> 16) & 1)))) & 0xFFFF;
    pip4Header->CheckSum = checksum;
    if (pip4Header->Proto == 1){
        checksum = (~(htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 2))))))) & 0xFFFF;
        for (int cnt=0;cnt<(htons((*(unsigned short*)(((void*)(((void*)pip4Header) + 2))))) - ((pip4Header->VerAndHeaderLength & 0xF) * 4));cnt++){
            if (cnt==1){continue;}
            checksum -= (htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + (cnt * 2)))))));
            if (((checksum >> 16) & 1)){checksum = ((checksum & 0xFFFF) - ((checksum >> 16) & 1)) & 0xFFFF;}
        }
        char checksumrec_icmp_code=((htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 0)))))) >> 8) & 0xFF;
        if ((checksumrec_icmp_code == 3 || checksumrec_icmp_code == 4 || checksumrec_icmp_code == 5 || checksumrec_icmp_code == 11) && ishavepreviousheader_for_icmp == false){
            ishavepreviousheader_for_icmp = true;
            decipchecksum((IP4Header*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 8))));
            ishavepreviousheader_for_icmp = false;
        }
        checksum = (~(htons((checksum & 0xFFFF) - ((checksum >> 16) & 1)))) & 0xFFFF;
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 2)))) = ((checksum >> (8 * 0)) & 0xFF);
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 3)))) = ((checksum >> (8 * 1)) & 0xFF);
    } else if (pip4Header->Proto == 6){
        checksum = (~(htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 16))))))) & 0xFFFF;
        checksum -= (htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 0))))));
        if (((checksum >> 16) & 1)){checksum = ((checksum & 0xFFFF) - ((checksum >> 16) & 1)) & 0xFFFF;}
        checksum -= (htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 2))))));
        if (((checksum >> 16) & 1)){checksum = ((checksum & 0xFFFF) - ((checksum >> 16) & 1)) & 0xFFFF;}
        for (int cnt=6;cnt<10;cnt++){
            checksum -= htons((*(short*)((&pip4Header->VerAndHeaderLength) + (cnt * 2))));
            if (((checksum >> 16) & 1)){checksum = ((checksum & 0xFFFF) - ((checksum >> 16) & 1)) & 0xFFFF;}
        }
        checksum = (~(htons((checksum & 0xFFFF) - ((checksum >> 16) & 1)))) & 0xFFFF;
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 16)))) = ((checksum >> (8 * 0)) & 0xFF);
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 17)))) = ((checksum >> (8 * 1)) & 0xFF);
    } else if (pip4Header->Proto == 17) {
        checksum = (~(htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 6))))))) & 0xFFFF;
        checksum -= (htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 0))))));
        if (((checksum >> 16) & 1)){checksum = ((checksum & 0xFFFF) - ((checksum >> 16) & 1)) & 0xFFFF;}
        checksum -= (htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 2))))));
        if (((checksum >> 16) & 1)){checksum = ((checksum & 0xFFFF) - ((checksum >> 16) & 1)) & 0xFFFF;}
        for (int cnt=6;cnt<10;cnt++){
            checksum -= htons((*(short*)((&pip4Header->VerAndHeaderLength) + (cnt * 2))));
            if (((checksum >> 16) & 1)){checksum = ((checksum & 0xFFFF) - ((checksum >> 16) & 1)) & 0xFFFF;}
        }
        checksum = (~(htons((checksum & 0xFFFF) - ((checksum >> 16) & 1)))) & 0xFFFF;
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 6)))) = ((checksum >> (8 * 0)) & 0xFF);
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 7)))) = ((checksum >> (8 * 1)) & 0xFF);
    }
    return;
}
void incipchecksum(IP4Header* pip4Header){
    unsigned int checksum = (~(htons(pip4Header->CheckSum))) & 0xFFFF;
    checksum += htons((*(short*)((&pip4Header->VerAndHeaderLength) + (4 * 2))));
    if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
    for (int cnt=6;cnt<10;cnt++){
        checksum += htons((*(short*)((&pip4Header->VerAndHeaderLength) + (cnt * 2))));
        if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
    }
    checksum = (~(htons((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)))) & 0xFFFF;
    pip4Header->CheckSum = checksum;
    if (pip4Header->Proto == 1){
        checksum = (~(htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 2))))))) & 0xFFFF;
        char checksumrec_icmp_code=((htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 0)))))) >> 8) & 0xFF;
        if ((checksumrec_icmp_code == 3 || checksumrec_icmp_code == 4 || checksumrec_icmp_code == 5 || checksumrec_icmp_code == 11) && ishavepreviousheader_for_icmp == false){
            ishavepreviousheader_for_icmp = true;
            memcpy((void*)(((char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 8)))) + 12),(void*)(((char*)((void*)pip4Header)) + 16), 4);
            incipchecksum((IP4Header*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 8))));
            ishavepreviousheader_for_icmp = false;
        }
        for (int cnt=0;cnt<(htons((*(unsigned short*)(((void*)(((void*)pip4Header) + 2))))) - ((pip4Header->VerAndHeaderLength & 0xF) * 4));cnt++){
            if (cnt==1){continue;}
            checksum += (htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + (cnt * 2)))))));
            if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
        }
        checksum = (~(htons((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)))) & 0xFFFF;
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 2)))) = ((checksum >> (8 * 0)) & 0xFF);
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 3)))) = ((checksum >> (8 * 1)) & 0xFF);
    } else if (pip4Header->Proto == 6){
        checksum = (~(htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 16))))))) & 0xFFFF;
        checksum += (htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 0))))));
        if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
        checksum += (htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 2))))));
        if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
        for (int cnt=6;cnt<10;cnt++){
            checksum += htons((*(short*)((&pip4Header->VerAndHeaderLength) + (cnt * 2))));
            if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
        }
        checksum = (~(htons((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)))) & 0xFFFF;
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 16)))) = ((checksum >> (8 * 0)) & 0xFF);
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 17)))) = ((checksum >> (8 * 1)) & 0xFF);
    } else if (pip4Header->Proto == 17) {
        checksum = (~(htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 6))))))) & 0xFFFF;
        checksum += (htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 0))))));
        if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
        checksum += (htons((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 2))))));
        if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
        for (int cnt=6;cnt<10;cnt++){
            checksum += htons((*(short*)((&pip4Header->VerAndHeaderLength) + (cnt * 2))));
            if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
        }
        checksum = (~(htons((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)))) & 0xFFFF;
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 6)))) = ((checksum >> (8 * 0)) & 0xFF);
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 7)))) = ((checksum >> (8 * 1)) & 0xFF);
    }
    return;
}

void ip4portswap(IP4Header* pip4Header){
    unsigned short porttmp = 0;
    if (pip4Header->Proto == 6 || pip4Header->Proto == 17){
        porttmp = ((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 2)))));
        ((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 2))))) = ((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 0)))));
        ((*(unsigned short*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 0))))) = porttmp;
    }
    return;
}

PseudoIP4HeaderandIPX pseudoIP4HeaderandIPX;

void calculateipchksum(IP4Header* pip4Header){
    //PseudoIP4HeaderandIPX pseudoIP4HeaderandIPX;
    unsigned int checksum = 0;
    pip4Header->CheckSum = 0;
    for (int cnt=0;cnt<((pip4Header->VerAndHeaderLength & 0xF) * 2);cnt++){
        if (cnt == 5) {continue;}
        checksum += htons((*(short*)((&pip4Header->VerAndHeaderLength) + (cnt * 2))));
        if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
    }
    pip4Header->CheckSum = (~(htons((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)))) & 0xFFFF;

    if (pip4Header->Proto == 6 || pip4Header->Proto == 17){
        //memset(&pseudoIP4HeaderandIPX.pseudoIP4Header,0,sizeof(pseudoIP4HeaderandIPX));
        memcpy(pseudoIP4HeaderandIPX.pseudoIP4Header.SRCIP,pip4Header->SRCIP,sizeof(pseudoIP4HeaderandIPX.pseudoIP4Header.SRCIP));
        memcpy(pseudoIP4HeaderandIPX.pseudoIP4Header.DSTIP,pip4Header->DSTIP,sizeof(pseudoIP4HeaderandIPX.pseudoIP4Header.DSTIP));
        pseudoIP4HeaderandIPX.pseudoIP4Header.Proto = pip4Header->Proto;
        memcpy(pseudoIP4HeaderandIPX.Payload,((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4),htons(pip4Header->Length) - ((pip4Header->VerAndHeaderLength & 0xF) * 4));
        if (pip4Header->Proto == 6){
            pseudoIP4HeaderandIPX.pseudoIP4Header.Length = htons(htons(pip4Header->Length) - ((pip4Header->VerAndHeaderLength & 0xF) * 4));
        } else if (pip4Header->Proto == 17){
            pseudoIP4HeaderandIPX.pseudoIP4Header.Length = *(unsigned short*)(((void*)&pseudoIP4HeaderandIPX.Payload + 4));
        }
    }
    if (pip4Header->Proto == 6){
        checksum = 0;
        int cnt=0;
        pseudoIP4HeaderandIPX.Payload[16] = 0;
        pseudoIP4HeaderandIPX.Payload[17] = 0;
        int delta = ((htons(pip4Header->Length) - ((pip4Header->VerAndHeaderLength & 0xF) * 4)) + 12);
        if (delta&1){ delta++; }
        for (cnt=0;cnt<delta;cnt += 2){
            checksum += htons((*(short*)((void*)(((void*)&pseudoIP4HeaderandIPX) + (cnt)))));
            if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
        }
        checksum = (~(htons((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)))) & 0xFFFF;
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 16)))) = ((checksum >> (8 * 0)) & 0xFF);
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 17)))) = ((checksum >> (8 * 1)) & 0xFF);
    } else if (pip4Header->Proto == 17) {
        checksum = 0;
        int cnt=0;
        pseudoIP4HeaderandIPX.Payload[6] = 0;
        pseudoIP4HeaderandIPX.Payload[7] = 0;
        int delta = (htons(*(unsigned short*)(((void*)&pseudoIP4HeaderandIPX.Payload + 4))) + 12);
        if (delta&1){ delta++; }
        for (cnt=0;cnt<delta;cnt += 2){
            checksum += htons((*(short*)((void*)(((void*)&pseudoIP4HeaderandIPX) + (cnt)))));
            if (((checksum >> 16) & 0xFFFF)){checksum = ((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)) & 0xFFFF;}
        }
        checksum = (~(htons((checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF)))) & 0xFFFF;
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 6)))) = ((checksum >> (8 * 0)) & 0xFF);
        (*(unsigned char*)(((void*)(((void*)pip4Header) + ((pip4Header->VerAndHeaderLength & 0xF) * 4) + 7)))) = ((checksum >> (8 * 1)) & 0xFF);
    }
    return;
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        usage();
        return 0;
    }

    if (argc == 2) {
        if (!memcmp("--help", argv[1], 6)) {
            usage();
            exit(0);
        } else if (!memcmp("-list", argv[1], 5)) {
            listInterfaces();
            exit(0);
        } else {
            fprintf(stdout, "Invalid parameter\n");
            usage();
            exit(1);
        }
    }

    char rti[16]{'\0'};
    unsigned char rtm[32]{'\0'};
    char rqi[16]{'\0'};
    unsigned char rqm[32]{'\0'};
    char msi[16]{'\0'};
    unsigned char msm[32]{'\0'};
    char mti[16]{'\0'};
    unsigned char mtm[32]{'\0'};
    char nsi[16]{'\0'};
    char ndi[16]{'\0'};
    char nsp[16]{'\0'};
    char ndp[16]{'\0'};
    char iInterfaceName[96]{'\0'};
    char oInterfaceName[96]{'\0'};
    int iInterval = 1;
    bool quite = false;
    bool sendonly = false;
    bool recvonly = false;

    bool isl3promisc = false;

    for (int i = 1; i < argc; i++) {
        if (!memcmp("-rti", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stdout, "Invalid reply to ip address, must be like 10.0.0.1\n");
                exit(1);
            }
            memccpy(rti, argv[++i], '\0', sizeof(rti));
            memcpy(rti4searchmac,rti,4);
        } else if (!memcmp("-rqi", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stdout, "Invalid request ip address, must be like 10.0.0.1\n");
                exit(1);
            }
            memccpy(rqi, argv[++i], '\0', sizeof(rqi));
        } else if (!memcmp("-msi", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stdout, "Invalid request ip address, must be like 10.0.0.1\n");
                exit(1);
            }
            memccpy(msi, argv[++i], '\0', sizeof(msi));
        } else if (!memcmp("-mti", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stdout, "Invalid request ip address, must be like 10.0.0.1\n");
                exit(1);
            }
            memccpy(mti, argv[++i], '\0', sizeof(mti));
        } else if (!memcmp("-nsi", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stdout, "Invalid request ip address, must be like 10.0.0.1\n");
                exit(1);
            }
            memccpy(nsi, argv[++i], '\0', sizeof(mti));
        } else if (!memcmp("-ndi", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stdout, "Invalid request ip address, must be like 10.0.0.1\n");
                exit(1);
            }
            memccpy(ndi, argv[++i], '\0', sizeof(mti));
        } else if (!memcmp("-nsp", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stdout, "Invalid request ip address, must be like 10.0.0.1\n");
                exit(1);
            }
            memccpy(nsp, argv[++i], '\0', sizeof(mti));
        } else if (!memcmp("-ndp", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stdout, "Invalid request ip address, must be like 10.0.0.1\n");
                exit(1);
            }
            memccpy(ndp, argv[++i], '\0', sizeof(mti));
        } else if (!memcmp("-rtm", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) != 17) {
                fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00\n");
                exit(1);
            }
            if (6 != sscanf(argv[i + 1], "%02x-%02x-%02x-%02x-%02x-%02x", &rtm[0], &rtm[1],
                            &rtm[2], &rtm[3], &rtm[4], &rtm[5])) {
                if (6 != sscanf(argv[i + 1], "%02x:%02x:%02x:%02x:%02x:%02x", &rtm[0],
                                &rtm[1], &rtm[2], &rtm[3], &rtm[4], &rtm[5])) {
                    fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00\n");
                    exit(1);
                }
            }
            i++;
        } else if (!memcmp("-rqm", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) != 17) {
                fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00\n");
                exit(1);
            }
            if (6 != sscanf(argv[i + 1], "%02x-%02x-%02x-%02x-%02x-%02x", &rqm[0], &rqm[1],
                            &rqm[2], &rqm[3], &rqm[4], &rqm[5])) {
                if (6 != sscanf(argv[i + 1], "%02x:%02x:%02x:%02x:%02x:%02x", &rqm[0],
                                &rqm[1], &rqm[2], &rqm[3], &rqm[4], &rqm[5])) {
                    fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00\n");
                    exit(1);
                }
            }
            i++;
        } else if (!memcmp("-msm", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) != 17) {
                fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00\n");
                exit(1);
            }
            if (6 != sscanf(argv[i + 1], "%02x-%02x-%02x-%02x-%02x-%02x", &msm[0], &msm[1],
                            &msm[2], &msm[3], &msm[4], &msm[5])) {
                if (6 != sscanf(argv[i + 1], "%02x:%02x:%02x:%02x:%02x:%02x", &msm[0],
                                &msm[1], &msm[2], &msm[3], &msm[4], &msm[5])) {
                    fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00\n");
                    exit(1);
                }
            }
            i++;
        } else if (!memcmp("-mtm", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) != 17) {
                fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00\n");
                exit(1);
            }
            if (6 != sscanf(argv[i + 1], "%02x-%02x-%02x-%02x-%02x-%02x", &mtm[0], &mtm[1],
                            &mtm[2], &mtm[3], &mtm[4], &mtm[5])) {
                if (6 != sscanf(argv[i + 1], "%02x:%02x:%02x:%02x:%02x:%02x", &mtm[0],
                                &mtm[1], &mtm[2], &mtm[3], &mtm[4], &mtm[5])) {
                    fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00\n");
                    exit(1);
                }
            }
            i++;
        } else if (!memcmp("-itval", argv[i], 6) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            char * pEnd;
            iInterval = (int) strtol(argv[++i], &pEnd, 10);
        } else if (!memcmp("-i", argv[i], 2) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 95) {
                fprintf(stdout, "Interface name is too long, Valid large length is 95\n");
                exit(1);
            }
            memccpy(iInterfaceName, argv[++i], '\0', 100);
        } else if (!memcmp("-o", argv[i], 2) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 95) {
                fprintf(stdout, "Interface name is too long, Valid large length is 95\n");
                exit(1);
            }
            memccpy(oInterfaceName, argv[++i], '\0', 100);
        } else if (!memcmp("-list", argv[i], 5)) {
            listInterfaces();
            exit(0);
        } else if (!memcmp("-q", argv[i], 2)) {
            quite = true;
        } else if (!memcmp("-nome", argv[i], 5)) {
            nomeflag = true;
        } else if (!memcmp("-poll", argv[i], 5)){
            enabledthepooling = true;
        } else if (!memcmp("-nat", argv[i], 4)) {
            nataddr4host = true;
        } else if (!memcmp("-sendonly", argv[i], 9)){
            sendonly = true;
        } else if (!memcmp("-recvonly", argv[i], 9)){
            recvonly = true;
        } else if (!memcmp("-promisc", argv[i], 9)){
            isl3promisc = true;
        } else if (!memcmp("-ttl", argv[i], 4)) {
            char * pEnd;
            incdec_ttl = (unsigned char) strtol(argv[++i], &pEnd, 10);
        } else {
            usage();
            exit(1);
        }
    }

    if (isEmpty(rti, sizeof(rti)) || isEmpty(rqi, sizeof(rqi))) {
        fprintf(stdout, "-rti and -rqi both must not be empty\n");
        exit(-1);
    }


    //if unspecified interface, so find out the first available interface name
    if (isEmpty(iInterfaceName, sizeof(iInterfaceName))) {
        struct ifaddrs *addrs{NULL}, *tmp{NULL};
        getifaddrs(&addrs);
        tmp = addrs;
        while (tmp)
        {
            if (!tmp->ifa_addr || tmp->ifa_addr->sa_family != AF_INET) {
                tmp = tmp->ifa_next;
                continue;
            }
            void *tmpAddrPtr = &((struct sockaddr_in *)tmp->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN]{'\0'};
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            if (!memcmp(addressBuffer, "127.0.0.1", 9)) {
                tmp = tmp->ifa_next;
                continue;
            }

            memccpy(iInterfaceName, tmp->ifa_name, '\0', 100);
            tmp = tmp->ifa_next;
        }
        if (NULL != addrs) {
            freeifaddrs(addrs);
        }

        if (isEmpty(iInterfaceName, sizeof(iInterfaceName))) {
            fprintf(stdout, "No available interface\n");
            exit(1);
        }
    }

    //if unspecified interface, so find out the first available interface name
    if (isEmpty(oInterfaceName, sizeof(oInterfaceName))) {
        struct ifaddrs *addrs{NULL}, *tmp{NULL};
        getifaddrs(&addrs);
        tmp = addrs;
        while (tmp)
        {
            if (!tmp->ifa_addr || tmp->ifa_addr->sa_family != AF_INET) {
                tmp = tmp->ifa_next;
                continue;
            }
            void *tmpAddrPtr = &((struct sockaddr_in *)tmp->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN]{'\0'};
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            if (!memcmp(addressBuffer, "127.0.0.1", 9)) {
                tmp = tmp->ifa_next;
                continue;
            }

            memccpy(oInterfaceName, tmp->ifa_name, '\0', 100);
            tmp = tmp->ifa_next;
        }
        if (NULL != addrs) {
            freeifaddrs(addrs);
        }

        if (isEmpty(oInterfaceName, sizeof(oInterfaceName))) {
            fprintf(stdout, "No available interface\n");
            exit(1);
        }
    }

    struct ifreq ifreq;
    struct ifreq ifreq_out;
    struct ifreq ifr_typeoftun_0;
    struct ifreq ifr_typeoftun_1;
    bool iInteristun = false;
    bool oInteristun = false;
    int ifindex4in = 0;
    int ifindex4out = 0;
    //memset(&ifreq_out, 0, sizeof(ifreq_out));
    strcpy(ifreq.ifr_name, iInterfaceName);
    strcpy(ifreq_out.ifr_name, oInterfaceName);
    strcpy(ifr_typeoftun_0.ifr_name, iInterfaceName);
    strcpy(ifr_typeoftun_1.ifr_name, oInterfaceName);
    bool isrenewedsocket = false;
    ipSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ipSock == -1) {
        perror("socket():");
        exit(1);
    }
    ipSock_out = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ipSock_out == -1) {
        perror("socket():");
        exit(1);
    }
aftersocketcreated:

    struct sockaddr_ll_1024 {
        unsigned short sll_family;
        unsigned short sll_protocol;
        int            sll_ifindex;
        unsigned short sll_hatype;
        unsigned char  sll_pkttype;
        unsigned char  sll_halen;
        unsigned char  sll_addr[1024];
    };

    struct sockaddr_ll_1024 sockAddr;
    sockAddr.sll_family = AF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ARP);
    sockAddr.sll_ifindex = if_nametoindex(iInterfaceName);

    struct sockaddr_ll_1024 sockAddr_out_arp;
    sockAddr_out_arp.sll_family = AF_PACKET;
    sockAddr_out_arp.sll_protocol = htons(ETH_P_ARP);
    sockAddr_out_arp.sll_ifindex = if_nametoindex(oInterfaceName);

    struct sockaddr_ll_1024 sockAddrghx;
    sockAddrghx.sll_family = AF_PACKET;
    sockAddrghx.sll_protocol = htons(ETH_P_IP);
    sockAddrghx.sll_ifindex = if_nametoindex(iInterfaceName);

    struct sockaddr_ll_1024 sockAddr_out;
    sockAddr_out.sll_family = AF_PACKET;
    sockAddr_out.sll_protocol = htons(ETH_P_IP);
    sockAddr_out.sll_ifindex = if_nametoindex(oInterfaceName);

    if (-1 == ioctl(ipSock.fdSock, SIOCGIFINDEX, &ifreq)) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    if (-1 == ioctl(ipSock_out.fdSock, SIOCGIFINDEX, &ifreq_out)) {
        perror("SIOCGIFINDEX");
        exit(1);
    }

    ifindex4in = ifreq.ifr_ifindex;
    ifindex4out = ifreq_out.ifr_ifindex;
    sockAddr.sll_ifindex = ifreq.ifr_ifindex;
    sockAddr_out_arp.sll_ifindex = ifreq_out.ifr_ifindex;
    sockAddrghx.sll_ifindex = ifreq.ifr_ifindex;
    sockAddr_out.sll_ifindex = ifreq_out.ifr_ifindex;
    //bind(ipSock.fdSock, (struct sockaddr *)&sockAddrghx, sizeof(sockAddrghx));
    //bind(ipSock_out.fdSock, (struct sockaddr *)&sockAddr_out, sizeof(sockAddr_out));
    sockAddr.sll_ifindex = ifreq.ifr_ifindex;

    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr.sll_pkttype = PACKET_BROADCAST;
    sockAddr.sll_halen = HW_ADDR_LENGTH;
    if (iInteristun == true){sockAddr.sll_pkttype=0;sockAddr.sll_hatype=0;memset(sockAddr.sll_addr,0,8);sockAddr.sll_halen=0;}
    memset(sockAddr.sll_addr + HW_ADDR_LENGTH, '\0', 2);
    sockAddr_out_arp.sll_ifindex = ifreq_out.ifr_ifindex;

    sockAddr_out_arp.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr_out_arp.sll_pkttype = PACKET_BROADCAST;
    sockAddr_out_arp.sll_halen = HW_ADDR_LENGTH;
    if (oInteristun == true){sockAddr_out_arp.sll_pkttype=0;sockAddr_out_arp.sll_hatype=0;memset(sockAddr_out_arp.sll_addr,0,8);sockAddr_out_arp.sll_halen=0;}
    memset(sockAddr_out_arp.sll_addr + HW_ADDR_LENGTH, '\0', 2);
    sockAddrghx.sll_ifindex = ifreq.ifr_ifindex;

    sockAddrghx.sll_hatype = htons(ARPHRD_ETHER);
    sockAddrghx.sll_pkttype = PACKET_BROADCAST;
    sockAddrghx.sll_halen = HW_ADDR_LENGTH;
    if (iInteristun == true){sockAddrghx.sll_pkttype=0;sockAddrghx.sll_hatype=0;memset(sockAddrghx.sll_addr,0,8); sockAddrghx.sll_halen=0;}
    memset(sockAddrghx.sll_addr + HW_ADDR_LENGTH, '\0', 2);

    sockAddr_out.sll_ifindex = ifreq_out.ifr_ifindex;

    sockAddr_out.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr_out.sll_pkttype = PACKET_BROADCAST;
    sockAddr_out.sll_halen = HW_ADDR_LENGTH;
    if (oInteristun == true){sockAddr_out.sll_pkttype=0;sockAddr_out.sll_hatype=0;memset(sockAddr_out.sll_addr,0,8); sockAddr_out.sll_halen=0;}
    memset(sockAddr_out.sll_addr + HW_ADDR_LENGTH, '\0', 2);

    if (-1 == ioctl(ipSock.fdSock, SIOCGIFHWADDR, &ifreq)) {
        perror("SIOCGIFHWADDR");
        exit(1);
    }

    if (-1 == ioctl(ipSock_out.fdSock, SIOCGIFHWADDR, &ifreq_out)) {
        perror("SIOCGIFHWADDR");
        exit(1);
    }

    for (int idx = 0; idx < HW_ADDR_LENGTH; idx++) {
        *(sockAddr.sll_addr + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
        *(sockAddr_out_arp.sll_addr + idx) = *(ifreq_out.ifr_hwaddr.sa_data + idx);
        *(sockAddrghx.sll_addr + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
        *(sockAddr_out.sll_addr + idx) = *(ifreq_out.ifr_hwaddr.sa_data + idx);
    }
    if (setsockopt(ipSock.fdSock, SOL_SOCKET, SO_BINDTODEVICE, (void*)&iInterfaceName, strlen(iInterfaceName)) < 0){
    }
    if (setsockopt(ipSock_out.fdSock, SOL_SOCKET, SO_BINDTODEVICE, (void*)&oInterfaceName, strlen(oInterfaceName)) < 0){
    }

    if (isEmpty(rqm, sizeof(rqm))) {
        for (int idx = 0; idx < HW_ADDR_LENGTH; idx++) {
            *(rqm + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
        }
    }

    char cmd[48]{'\0'};
    sprintf(cmd, "cat /proc/net/arp | grep '^%s\\s'", &rti);
    std::vector<std::string> outputLst = getCmdOutput(cmd);
    std::regex rgx("\\s+(\\w{2}\\:\\w{2}\\:\\w{2}\\:\\w{2}\\:\\w{2}\\:\\w{2})");
    std::smatch matches;
    for (int i = 0; i < outputLst.size(); i++) {
        std::string oneRow =  outputLst.at(i);
        if (!std::regex_search(oneRow, matches, rgx)) {
            continue;
        }

        if (2 == matches.size()) {
            sscanf(matches[1].str().c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", &rtm[0], &rtm[1], &rtm[2], &rtm[3], &rtm[4], &rtm[5]);
        }
        break;
    }

    if (isEmpty(rtm, sizeof(rtm))) {
        //to do: get mac address through to send arp request and receive the response
        getARPReplyMAC(ipSock.fdSock, iInterfaceName, rti, rtm);
        if (isEmpty(rtm, sizeof(rtm)) && iInteristun == false) {
            fprintf(stdout, "Can not found %s mac address from arp cache, Please try to ping %s firstly\n", rti, rti);
            exit(1);
        }
    }

    if (-1 == ioctl(ipSock.fdSock, SIOCGIFMTU, &ifreq)) {
        perror("SIOCGIFMTU");
        exit(1);
    }
    if (-1 == ioctl(ipSock_out.fdSock, SIOCGIFMTU, &ifreq_out)) {
        perror("SIOCGIFMTU");
        exit(1);
    }

    unsigned char buf[sizeof(MACHeader)]{'\0'};
    /*unsigned char ghxbuf[65536]{'\0'};
    unsigned char ghybuf[sizeof(MACHeader)]{'\0'};
    unsigned char ghzbuf[65536]{'\0'};*/

    if (-1 == ioctl(ipSock.fdSock, SIOCGIFFLAGS, &ifreq)) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    if (-1 == ioctl(ipSock_out.fdSock, SIOCGIFFLAGS, &ifreq_out)) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    if (!(ifreq.ifr_flags & IFF_BROADCAST) && (ifreq.ifr_flags & IFF_POINTOPOINT) && (ifreq.ifr_flags & IFF_NOARP)){
        iInteristun = true;
#if 0
        sockAddr.sll_hatype = htons(ifreq.ifr_hwaddr.sa_family);
        sockAddr.sll_pkttype = PACKET_HOST;
        sockAddr.sll_family = AF_INET;
        if (isrenewedsocket==false){
            isrenewedsocket = true;
            //close(ipSock.fdSock);
            ipSock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
            if (ipSock == -1) {
                perror("socket():");
                exit(1);
            }
            memset(&ifreq,0,sizeof(ifreq));
            memset(&ifr_typeoftun_0,0,sizeof(ifr_typeoftun_0));
            strcpy(ifreq.ifr_name, iInterfaceName);
            strcpy(ifr_typeoftun_0.ifr_name, iInterfaceName);
            goto aftersocketcreated;
        }else{
            isrenewedsocket = false;
        }
#endif
    }
    if (!(ifreq_out.ifr_flags & IFF_BROADCAST) && (ifreq_out.ifr_flags & IFF_POINTOPOINT) && (ifreq_out.ifr_flags & IFF_NOARP)){
        oInteristun = true;
#if 0
        sockAddr_out.sll_hatype = htons(ifreq_out.ifr_hwaddr.sa_family);
        sockAddr_out.sll_pkttype = PACKET_HOST;
        sockAddr_out.sll_family = AF_INET;
        if (isrenewedsocket==false){
            isrenewedsocket = true;
            //close(ipSock_out.fdSock);
            ipSock_out = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
            if (ipSock_out == -1) {
                perror("socket():");
                exit(1);
            }
            memset(&ifreq_out,0,sizeof(ifreq_out));
            memset(&ifr_typeoftun_1,0,sizeof(ifr_typeoftun_1));
            strcpy(ifreq_out.ifr_name, oInterfaceName);
            strcpy(ifr_typeoftun_1.ifr_name, oInterfaceName);
            goto aftersocketcreated;
        }else{
            isrenewedsocket = false;
        }
#endif
    }

    int valforpiog = 1;

    if (setsockopt(ipSock.fdSock, SOL_PACKET, PACKET_IGNORE_OUTGOING, (void*)&valforpiog, sizeof(valforpiog)) < 0){
    }
    if (setsockopt(ipSock_out.fdSock, SOL_PACKET, PACKET_IGNORE_OUTGOING, (void*)&valforpiog, sizeof(valforpiog)) < 0){
    }

    /*bind(ipSock.fdSock,(struct sockaddr*)&sockAddr,sizeof(sockAddr));
    bind(ipSock_out.fdSock,(struct sockaddr*)&sockAddr_out,sizeof(sockAddr_out));*/

    {
        //construct arp response
        MACHeader &pMAC = (MACHeader&)buf;
        MACHeader &pMAC2 = (MACHeader&)ghxbuf;
        memcpy(pMAC.destMACAddr, rtm, sizeof(pMAC.destMACAddr));
        memcpy(pMAC.arpHeader.TargetMAC, rtm, sizeof(pMAC.arpHeader.TargetMAC));
        memcpy(pMAC.srcMACAddr, rqm, sizeof(pMAC.srcMACAddr));
        memcpy(pMAC.arpHeader.SenderMAC, rqm, sizeof(pMAC.arpHeader.SenderMAC));

        pMAC.upperType = htons(0x0806);
        pMAC.arpHeader.HWType = htons(0x0001);
        pMAC.arpHeader.ProcType = htons(0x0800);
        pMAC.arpHeader.HWSize = 6;
        pMAC.arpHeader.ProcSize = 4;
        pMAC.arpHeader.Opcode = htons(0x0002);
        in_addr_t tmp = inet_addr(rqi);
        memcpy(pMAC.arpHeader.SenderIP, (void*)(&tmp), sizeof(in_addr_t));
        tmp = inet_addr(msi);
        memcpy(mysubnetmask, (void*)(&tmp), sizeof(in_addr_t));
        tmp = inet_addr(rti);
        memcpy(pMAC.arpHeader.TargetIP, (void*)(&tmp), sizeof(in_addr_t));
        tmp = inet_addr(mti);
        memcpy(mti_binary, (void*)(&tmp), sizeof(in_addr_t));
        tmp = inet_addr(nsi);
        memcpy(nsi_binary, (void*)(&tmp), sizeof(in_addr_t));
        tmp = inet_addr(ndi);
        memcpy(ndi_binary, (void*)(&tmp), sizeof(in_addr_t));
        tmp = inet_addr(nsp);
        memcpy(nsp_binary, (void*)(&tmp), sizeof(in_addr_t));
        tmp = inet_addr(ndp);
        memcpy(ndp_binary, (void*)(&tmp), sizeof(in_addr_t));
        (*(unsigned int *)&myinterfaceip) = (unsigned int)inet_addr(rqi);
    }

    long unsigned int sockAddrghxsiz;
    long unsigned int sockAddr_outsiz;

    //fd_set fds, readfds;
    //bind(ipSock.fdSock, (struct sockaddr *)&sockAddrghx, sizeof(sockAddrghx));
    //bind(ipSock_out.fdSock, (struct sockaddr *)&sockAddr_out, sizeof(sockAddr_out));
    epoll_event ev, ev_in, ev_out, events[13];
    int sd_listen;
    int epfd = epoll_create(1);

    //FD_ZERO(&readfds);
    //FD_SET(ipSock.fdSock, &readfds);
    //FD_SET(ipSock_out.fdSock, &readfds);
    //int max_fd = std::max(ipSock.fdSock, ipSock_out.fdSock) + 1;
    memset(&ev_in,0,sizeof(epoll_event));
    ev_in.events = EPOLLIN;
    ev_in.data.fd = ipSock.fdSock;
    epoll_ctl(epfd,EPOLL_CTL_ADD,ipSock.fdSock,&ev_in);
    memset(&ev_out,0,sizeof(epoll_event));
    ev_out.events = EPOLLIN;
    ev_out.data.fd = ipSock_out.fdSock;
    epoll_ctl(epfd,EPOLL_CTL_ADD,ipSock_out.fdSock,&ev_out);

    //fprintf(stdout, "%d.%d.%d.%d", mti_binary[0], mti_binary[1], mti_binary[2], mti_binary[3]);

    bool unfunctedpart = false;
    bool unfunctedpart2 = false;
    srand((unsigned)time(NULL));

#if 0
    if (fork() != 0){
        usleep(120);
        srand((unsigned)time(NULL));
        unfunctedpart = true;
        unfunctedpart2 = true;
        //usleep(33);
        //usleep(34);
        //usleep(534);
        //usleep(573);
        //usleep(634);
        //usleep(637);
        //usleep(577);
        //usleep(377);
        //usleep(877);
        //usleep(1877);
        //usleep(1937);
        //usleep(3877);
        usleep((rand() % 93) + 87);
        usleep(1320);
    }else{
        usleep(1320);
        srand((unsigned)time(NULL));
        usleep(120);
    }
#endif

    bool ignorein=false,ignoreout=false;
    int ignorecount=0;
    timeofpooling = time(0);
    memset(ghxbuf,0,1514);
    memset(ghzbuf,0,1514);
    memcpy(ghybuf,buf,sizeof(MACHeader));
    memcpy(buf_arpin,buf,sizeof(MACHeader));
    memcpy(buf_arpout,buf,sizeof(MACHeader));
    iovec msg_iov_pktin, msg_iov_pktout;
    msghdr msg_header_pktin, msg_header_pktout;
    unsigned short hatype_in = ARPHRD_ETHER;
    unsigned short hatype_out = ARPHRD_ETHER;

    /*int pkt_ignore_og_enable = 1;
    if (setsockopt(ipSock.fdSock, SOL_SOCKET, PACKET_IGNORE_OUTGOING, (void*)&pkt_ignore_og_enable, sizeof(pkt_ignore_og_enable)) < 0){
    }
    if (setsockopt(ipSock_out.fdSock, SOL_SOCKET, PACKET_IGNORE_OUTGOING, (void*)&pkt_ignore_og_enable, sizeof(pkt_ignore_og_enable)) < 0){
    }*/

    for (;;){
        sockAddrghx.sll_protocol = htons(ETH_P_ALL);
        sockAddr_out.sll_protocol = htons(ETH_P_ALL);
        int ghxsiz = 0;
        int ghzsiz = 0;
        int count4retry=0;
        int count4retry2=0;
        unsigned int checksum = 0;
        //memset(ghxbuf,0,1514);
        //memset(ghzbuf,0,1514);
        bool transmac_ip_success = false;
        MACHeader &pMAC = (MACHeader&)buf;
        MACHeader &pMAC2 = (MACHeader&)ghxbuf;
        MACHeader &pMAC3 = (MACHeader&)ghzbuf;
        MACHeader &pMAC_arpin = (MACHeader&)buf_arpin;
        MACHeader &pMAC_arpout = (MACHeader&)buf_arpout;
        MACIP4Header &pIP4MAC = (MACIP4Header&)buf;
        MACIP4Header &pIP4MAC2 = (MACIP4Header&)ghxbuf;
        MACIP4Header &pIP4MAC3 = (MACIP4Header&)ghzbuf;
        //memcpy(ghybuf,buf,sizeof(MACHeader));
gettingpacket:
        //memcpy(&fds, &readfds, sizeof(fd_set));
        /*if (select(max_fd, &fds, NULL, NULL, NULL) < 0){
            perror("Selecting failure");
        }*/
        int n_events = epoll_wait(epfd, events, 13, -1);
        if(n_events < 0){
            perror("Selecting failure");
        }
        for(int cnt_of_epfd=0;cnt_of_epfd<n_events;cnt_of_epfd++){
        /*ghxsiz = 0;
        ghzsiz = 0;*/
        if (events[cnt_of_epfd].data.fd<0){continue;}
        transmac_ip_success = false;
    if (events[cnt_of_epfd].data.fd==ipSock.fdSock){
        transmac_ip_success = false;
        if (events[cnt_of_epfd].data.fd==ipSock.fdSock){
        //if (!FD_ISSET(ipSock.fdSock, &fds)){ goto pMAC3_maniplation; }
        sockAddrghx.sll_family = AF_PACKET;
        sockAddrghx.sll_halen = HW_ADDR_LENGTH;
        sockAddrghx.sll_protocol = htons(ETH_P_ALL);
        if (iInteristun == true){memset(sockAddrghx.sll_addr,0,8);sockAddrghx.sll_halen=0;sockAddrghx.sll_protocol = htons(ETH_P_IP);}
        sockAddr.sll_ifindex = ifindex4in;
        sockAddr_out_arp.sll_ifindex = ifindex4out;
        sockAddrghx.sll_ifindex = ifindex4in;
        sockAddr_out.sll_ifindex = ifindex4out;
        sockAddrghxsiz = sizeof(sockAddrghx);
        /*if (-1 == (ghxsiz = recvfrom(ipSock.fdSock, ghxbuf + (iInteristun ? 14 : 0), sizeof(ghxbuf), 0, (struct sockaddr *)&sockAddrghx, (socklen_t*)&sockAddrghxsiz))) {
            perror("Receiveing failure(iInterface)");
        }*/
        msg_iov_pktin.iov_base = (((void*)&ghxbuf) + ((unsigned long long)(iInteristun ? 14 : 0)));
        msg_iov_pktin.iov_len = (sizeof(ghxbuf) - (iInteristun ? 14 : 0));
        msg_header_pktin.msg_name = &sockAddrghx;
        msg_header_pktin.msg_namelen = sockAddrghxsiz;
        msg_header_pktin.msg_iov = &msg_iov_pktin;
        msg_header_pktin.msg_iovlen = 1;
        msg_header_pktin.msg_control = NULL;
        msg_header_pktin.msg_controllen = 0;
        msg_header_pktin.msg_flags = 0;
        if (-1 == (ghxsiz = recvmsg(ipSock.fdSock, &msg_header_pktin, 0))) {
            if (iInteristun==false) {perror("Receiveing failure(iInterface)");}
            ghxsiz = ifreq.ifr_mtu + 14;
        }
        if (sockAddrghx.sll_pkttype!=PACKET_HOST && sockAddrghx.sll_pkttype!=PACKET_MULTICAST && sockAddrghx.sll_pkttype!=PACKET_BROADCAST && sockAddrghx.sll_pkttype!=PACKET_OTHERHOST){ ghxsiz = 0; goto pMAC3_maniplation_; }
        if (!(sockAddrghx.sll_pkttype!=PACKET_HOST && sockAddrghx.sll_pkttype!=PACKET_MULTICAST && sockAddrghx.sll_pkttype!=PACKET_BROADCAST && sockAddrghx.sll_pkttype!=PACKET_OTHERHOST) && (sockAddrghx.sll_ifindex == ifindex4in)){
        if (iInteristun == true){
            sockAddrghx.sll_protocol == htons(ETH_P_IP);
            memcpy(pIP4MAC2.srcMACAddr, pMAC.destMACAddr, sizeof(pMAC.srcMACAddr));
            memcpy(pIP4MAC2.destMACAddr, pMAC.srcMACAddr, sizeof(pMAC.srcMACAddr));
            pIP4MAC2.upperType = htons(ETH_P_IP);
        }
        sockAddr.sll_ifindex = ifindex4in;
        sockAddr_out_arp.sll_ifindex = ifindex4out;
        sockAddrghx.sll_ifindex = ifindex4in;
        sockAddr_out.sll_ifindex = ifindex4out;
        if (((sockAddrghx.sll_protocol == htons(ETH_P_ARP)) || (sockAddrghx.sll_protocol == htons(ETH_P_IP))) && !((pIP4MAC2.srcMACAddr[0] == pMAC.srcMACAddr[0]) && (pIP4MAC2.srcMACAddr[1] == pMAC.srcMACAddr[1]) && (pIP4MAC2.srcMACAddr[2] == pMAC.srcMACAddr[2]) && (pIP4MAC2.srcMACAddr[3] == pMAC.srcMACAddr[3]) && (pIP4MAC2.srcMACAddr[4] == pMAC.srcMACAddr[4]) && (pIP4MAC2.srcMACAddr[5] == pMAC.srcMACAddr[5]))){
        if (((((pIP4MAC2.ip4Header.DSTIP[0] & mysubnetmask[0]) == (pMAC.arpHeader.SenderIP[0] & mysubnetmask[0])) && ((pIP4MAC2.ip4Header.DSTIP[1] & mysubnetmask[1]) == (pMAC.arpHeader.SenderIP[1] & mysubnetmask[1])) && ((pIP4MAC2.ip4Header.DSTIP[2] & mysubnetmask[2]) == (pMAC.arpHeader.SenderIP[2] & mysubnetmask[2])) && ((pIP4MAC2.ip4Header.DSTIP[3] & mysubnetmask[3]) == (pMAC.arpHeader.SenderIP[3] & mysubnetmask[3]))) || (isl3promisc == true)) && ((((pMAC2.destMACAddr[0] == pMAC.srcMACAddr[0]) && (pMAC2.destMACAddr[1] == pMAC.srcMACAddr[1]) && (pMAC2.destMACAddr[2] == pMAC.srcMACAddr[2]) && (pMAC2.destMACAddr[3] == pMAC.srcMACAddr[3]) && (pMAC2.destMACAddr[4] == pMAC.srcMACAddr[4]) && (pMAC2.destMACAddr[5] == pMAC.srcMACAddr[5]))) && (sockAddrghx.sll_protocol == htons(ETH_P_IP)) && (nomeflag == false || ((*(unsigned int*)&myinterfaceip) != (*(unsigned int*)&pIP4MAC2.ip4Header.SRCIP))))){
        //if (ignorein==true){if (ignorecount==1){ignorein=false; ignorecount=0;}else{ignorecount++;} continue;}
        //if ((((pIP4MAC2.ip4Header.DSTIP[0] == ndi_binary[0] && pIP4MAC2.ip4Header.DSTIP[1] == ndi_binary[1] && pIP4MAC2.ip4Header.DSTIP[2] == ndi_binary[2] && pIP4MAC2.ip4Header.DSTIP[3] == ndi_binary[3]) && !(ndi_binary[0]==0 && ndi_binary[1]==0 && ndi_binary[2]==0 && ndi_binary[3]==0)) || ((((pIP4MAC2.ip4Header.DSTIP[0] & mysubnetmask[0]) == (pMAC.arpHeader.SenderIP[0] & mysubnetmask[0])) && ((pIP4MAC2.ip4Header.DSTIP[1] & mysubnetmask[1]) == (pMAC.arpHeader.SenderIP[1] & mysubnetmask[1])) && ((pIP4MAC2.ip4Header.DSTIP[2] & mysubnetmask[2]) == (pMAC.arpHeader.SenderIP[2] & mysubnetmask[2])) && ((pIP4MAC2.ip4Header.DSTIP[3] & mysubnetmask[3]) == (pMAC.arpHeader.SenderIP[3] & mysubnetmask[3]))) && (ndi_binary[0]==0 && ndi_binary[1]==0 && ndi_binary[2]==0 && ndi_binary[3]==0))) && ((((pMAC2.destMACAddr[0] == pMAC.srcMACAddr[0]) && (pMAC2.destMACAddr[1] == pMAC.srcMACAddr[1]) && (pMAC2.destMACAddr[2] == pMAC.srcMACAddr[2]) && (pMAC2.destMACAddr[3] == pMAC.srcMACAddr[3]) && (pMAC2.destMACAddr[4] == pMAC.srcMACAddr[4]) && (pMAC2.destMACAddr[5] == pMAC.srcMACAddr[5]))) && (sockAddrghx.sll_protocol == htons(ETH_P_IP)) && (nomeflag == false || ((*(unsigned int*)&myinterfaceip) != (*(unsigned int*)&pIP4MAC2.ip4Header.SRCIP))))){
        //if ((!((pIP4MAC2.ip4Header.DSTIP[0]==0 && pIP4MAC2.ip4Header.DSTIP[1]==0 && pIP4MAC2.ip4Header.DSTIP[2]==0 && pIP4MAC2.ip4Header.DSTIP[3]==0) || (pIP4MAC2.ip4Header.DSTIP[0]==255 && pIP4MAC2.ip4Header.DSTIP[1]==255 && pIP4MAC2.ip4Header.DSTIP[2]==255 && pIP4MAC2.ip4Header.DSTIP[3]==255))) && ((((pMAC2.destMACAddr[0] == pMAC.srcMACAddr[0]) && (pMAC2.destMACAddr[1] == pMAC.srcMACAddr[1]) && (pMAC2.destMACAddr[2] == pMAC.srcMACAddr[2]) && (pMAC2.destMACAddr[3] == pMAC.srcMACAddr[3]) && (pMAC2.destMACAddr[4] == pMAC.srcMACAddr[4]) && (pMAC2.destMACAddr[5] == pMAC.srcMACAddr[5]))) && (sockAddrghx.sll_protocol == htons(ETH_P_IP)) && (nomeflag == false || ((*(unsigned int*)&myinterfaceip) != (*(unsigned int*)&pIP4MAC2.ip4Header.SRCIP))))){
            if (recvonly){ goto pMAC3_maniplation; }
            //if (unfunctedpart == true) { unfunctedpart = false; goto pMAC3_maniplation; }
            //unfunctedpart = true;
            //memcpy(buf,ghybuf,sizeof(MACHeader));
            memcpy(pIP4MAC2.srcMACAddr, mtm, sizeof(pMAC.srcMACAddr));
            memcpy(pIP4MAC2.destMACAddr, msm, sizeof(pMAC.srcMACAddr));
            /*for(int cnt=0;cnt<6;cnt++){
                *(char*)(&pIP4MAC2.srcMACAddr)[cnt] = *(char*)(&mtm)[cnt];
                *(char*)(&pIP4MAC2.destMACAddr)[cnt] = *(char*)(&msm)[cnt];
            }*/
            //pIP4MAC2.ip4Header.TTL--;
            if ((((nsp_binary[0] & mysubnetmask[0]) == (pIP4MAC2.ip4Header.DSTIP[0] & mysubnetmask[0])) && ((nsp_binary[1] & mysubnetmask[1]) == (pIP4MAC2.ip4Header.DSTIP[1] & mysubnetmask[1])) && ((nsp_binary[2] & mysubnetmask[2]) == (pIP4MAC2.ip4Header.DSTIP[2] & mysubnetmask[2])) && ((nsp_binary[3] & mysubnetmask[3]) == (pIP4MAC2.ip4Header.DSTIP[3] & mysubnetmask[3])))) {
                decipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
                pIP4MAC2.ip4Header.DSTIP[0] = (ndp_binary[0] & mysubnetmask[0]) | (pIP4MAC2.ip4Header.DSTIP[0] & ~mysubnetmask[0]);
                pIP4MAC2.ip4Header.DSTIP[1] = (ndp_binary[1] & mysubnetmask[1]) | (pIP4MAC2.ip4Header.DSTIP[1] & ~mysubnetmask[1]);
                pIP4MAC2.ip4Header.DSTIP[2] = (ndp_binary[2] & mysubnetmask[2]) | (pIP4MAC2.ip4Header.DSTIP[2] & ~mysubnetmask[2]);
                pIP4MAC2.ip4Header.DSTIP[3] = (ndp_binary[3] & mysubnetmask[3]) | (pIP4MAC2.ip4Header.DSTIP[3] & ~mysubnetmask[3]);
                //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                incipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
            } else if ((((ndp_binary[0] & mysubnetmask[0]) == (pIP4MAC2.ip4Header.SRCIP[0] & mysubnetmask[0])) && ((ndp_binary[1] & mysubnetmask[1]) == (pIP4MAC2.ip4Header.SRCIP[1] & mysubnetmask[1])) && ((ndp_binary[2] & mysubnetmask[2]) == (pIP4MAC2.ip4Header.SRCIP[2] & mysubnetmask[2])) && ((ndp_binary[3] & mysubnetmask[3]) == (pIP4MAC2.ip4Header.SRCIP[3] & mysubnetmask[3])))) {
                decipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
                pIP4MAC2.ip4Header.SRCIP[0] = (nsp_binary[0] & mysubnetmask[0]) | (pIP4MAC2.ip4Header.SRCIP[0] & ~mysubnetmask[0]);
                pIP4MAC2.ip4Header.SRCIP[1] = (nsp_binary[1] & mysubnetmask[1]) | (pIP4MAC2.ip4Header.SRCIP[1] & ~mysubnetmask[1]);
                pIP4MAC2.ip4Header.SRCIP[2] = (nsp_binary[2] & mysubnetmask[2]) | (pIP4MAC2.ip4Header.SRCIP[2] & ~mysubnetmask[2]);
                pIP4MAC2.ip4Header.SRCIP[3] = (nsp_binary[3] & mysubnetmask[3]) | (pIP4MAC2.ip4Header.SRCIP[3] & ~mysubnetmask[3]);
                //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                incipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
            } else if ((((ndp_binary[0] & mysubnetmask[0]) == (pIP4MAC2.ip4Header.DSTIP[0] & mysubnetmask[0])) && ((ndp_binary[1] & mysubnetmask[1]) == (pIP4MAC2.ip4Header.DSTIP[1] & mysubnetmask[1])) && ((ndp_binary[2] & mysubnetmask[2]) == (pIP4MAC2.ip4Header.DSTIP[2] & mysubnetmask[2])) && ((ndp_binary[3] & mysubnetmask[3]) == (pIP4MAC2.ip4Header.DSTIP[3] & mysubnetmask[3])))) {
                decipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
                pIP4MAC2.ip4Header.DSTIP[0] = (nsp_binary[0] & mysubnetmask[0]) | (pIP4MAC2.ip4Header.DSTIP[0] & ~mysubnetmask[0]);
                pIP4MAC2.ip4Header.DSTIP[1] = (nsp_binary[1] & mysubnetmask[1]) | (pIP4MAC2.ip4Header.DSTIP[1] & ~mysubnetmask[1]);
                pIP4MAC2.ip4Header.DSTIP[2] = (nsp_binary[2] & mysubnetmask[2]) | (pIP4MAC2.ip4Header.DSTIP[2] & ~mysubnetmask[2]);
                pIP4MAC2.ip4Header.DSTIP[3] = (nsp_binary[3] & mysubnetmask[3]) | (pIP4MAC2.ip4Header.DSTIP[3] & ~mysubnetmask[3]);
                //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                incipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
            } else if ((((nsp_binary[0] & mysubnetmask[0]) == (pIP4MAC2.ip4Header.SRCIP[0] & mysubnetmask[0])) && ((nsp_binary[1] & mysubnetmask[1]) == (pIP4MAC2.ip4Header.SRCIP[1] & mysubnetmask[1])) && ((nsp_binary[2] & mysubnetmask[2]) == (pIP4MAC2.ip4Header.SRCIP[2] & mysubnetmask[2])) && ((nsp_binary[3] & mysubnetmask[3]) == (pIP4MAC2.ip4Header.SRCIP[3] & mysubnetmask[3])))) {
                decipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
                pIP4MAC2.ip4Header.SRCIP[0] = (ndp_binary[0] & mysubnetmask[0]) | (pIP4MAC2.ip4Header.SRCIP[0] & ~mysubnetmask[0]);
                pIP4MAC2.ip4Header.SRCIP[1] = (ndp_binary[1] & mysubnetmask[1]) | (pIP4MAC2.ip4Header.SRCIP[1] & ~mysubnetmask[1]);
                pIP4MAC2.ip4Header.SRCIP[2] = (ndp_binary[2] & mysubnetmask[2]) | (pIP4MAC2.ip4Header.SRCIP[2] & ~mysubnetmask[2]);
                pIP4MAC2.ip4Header.SRCIP[3] = (ndp_binary[3] & mysubnetmask[3]) | (pIP4MAC2.ip4Header.SRCIP[3] & ~mysubnetmask[3]);
                //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                incipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
            }
            if (((nsi_binary[0] == pIP4MAC2.ip4Header.DSTIP[0]) && (nsi_binary[1] == pIP4MAC2.ip4Header.DSTIP[1]) && (nsi_binary[2] == pIP4MAC2.ip4Header.DSTIP[2]) && (nsi_binary[3] == pIP4MAC2.ip4Header.DSTIP[3]))) {
                decipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
                pIP4MAC2.ip4Header.DSTIP[0] = ndi_binary[0];
                pIP4MAC2.ip4Header.DSTIP[1] = ndi_binary[1];
                pIP4MAC2.ip4Header.DSTIP[2] = ndi_binary[2];
                pIP4MAC2.ip4Header.DSTIP[3] = ndi_binary[3];
                //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                /*if (incdec_ttl!=0){
                    pIP4MAC2.ip4Header.TTL += incdec_ttl;
                }*/
                incipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
            } else if (((ndi_binary[0] == pIP4MAC2.ip4Header.SRCIP[0]) && (ndi_binary[1] == pIP4MAC2.ip4Header.SRCIP[1]) && (ndi_binary[2] == pIP4MAC2.ip4Header.SRCIP[2]) && (ndi_binary[3] == pIP4MAC2.ip4Header.SRCIP[3]))) {
                decipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
                pIP4MAC2.ip4Header.SRCIP[0] = nsi_binary[0];
                pIP4MAC2.ip4Header.SRCIP[1] = nsi_binary[1];
                pIP4MAC2.ip4Header.SRCIP[2] = nsi_binary[2];
                pIP4MAC2.ip4Header.SRCIP[3] = nsi_binary[3];
                //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                /*if (incdec_ttl!=0){
                    pIP4MAC2.ip4Header.TTL += incdec_ttl;
                }*/
                incipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
            } else if (((ndi_binary[0] == pIP4MAC2.ip4Header.DSTIP[0]) && (ndi_binary[1] == pIP4MAC2.ip4Header.DSTIP[1]) && (ndi_binary[2] == pIP4MAC2.ip4Header.DSTIP[2]) && (ndi_binary[3] == pIP4MAC2.ip4Header.DSTIP[3]))) {
                decipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
                pIP4MAC2.ip4Header.DSTIP[0] = nsi_binary[0];
                pIP4MAC2.ip4Header.DSTIP[1] = nsi_binary[1];
                pIP4MAC2.ip4Header.DSTIP[2] = nsi_binary[2];
                pIP4MAC2.ip4Header.DSTIP[3] = nsi_binary[3];
                //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                /*if (incdec_ttl!=0){
                    pIP4MAC2.ip4Header.TTL += incdec_ttl;
                }*/
                incipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
            } else if (((nsi_binary[0] == pIP4MAC2.ip4Header.SRCIP[0]) && (nsi_binary[1] == pIP4MAC2.ip4Header.SRCIP[1]) && (nsi_binary[2] == pIP4MAC2.ip4Header.SRCIP[2]) && (nsi_binary[3] == pIP4MAC2.ip4Header.SRCIP[3]))) {
                decipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
                pIP4MAC2.ip4Header.SRCIP[0] = ndi_binary[0];
                pIP4MAC2.ip4Header.SRCIP[1] = ndi_binary[1];
                pIP4MAC2.ip4Header.SRCIP[2] = ndi_binary[2];
                pIP4MAC2.ip4Header.SRCIP[3] = ndi_binary[3];
                //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                /*if (incdec_ttl!=0){
                    pIP4MAC2.ip4Header.TTL += incdec_ttl;
                }*/
                incipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
            } /*else if (incdec_ttl!=0){
                decipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
                pIP4MAC2.ip4Header.TTL += incdec_ttl;
                incipchecksum((IP4Header*)&pIP4MAC2.ip4Header);
            }*/
            sockAddr.sll_ifindex = ifindex4in;
            sockAddr_out_arp.sll_ifindex = ifindex4out;
            sockAddrghx.sll_ifindex = ifindex4in;
            sockAddr_out.sll_ifindex = ifindex4out;
            msg_iov_pktout.iov_base = (((void*)&ghxbuf) + ((unsigned long long)(oInteristun ? 14 : 0)));
            msg_iov_pktout.iov_len = (((ghxsiz & 0xFFFF) < (ifreq_out.ifr_mtu + (oInteristun ? 0 : 14))) ? (ghxsiz & 0xFFFF) : (ifreq_out.ifr_mtu + (oInteristun ? 0 : 14)));
            msg_header_pktout.msg_name = &sockAddr_out;
            msg_header_pktout.msg_namelen = sizeof(sockAddr_out);
            msg_header_pktout.msg_iov = &msg_iov_pktout;
            msg_header_pktout.msg_iovlen = 1;
            msg_header_pktout.msg_control = NULL;
            msg_header_pktout.msg_controllen = 0;
            msg_header_pktout.msg_flags = 0;
            sockAddr_out.sll_protocol = htons(ETH_P_IP);
            hatype_in = sockAddr_out.sll_hatype; sockAddr_out.sll_hatype = 0;
            sockAddr_out.sll_pkttype=0;
            sockAddr_out.sll_halen=0;
            memset(sockAddr_out.sll_addr,0,8);
            /*if (-1 == sendto(ipSock_out.fdSock, ghxbuf + (oInteristun ? 14 : 0), (((ghxsiz & 0xFFFF) < (ifreq_out.ifr_mtu + (oInteristun ? 0 : 14))) ? (ghxsiz & 0xFFFF) : (ifreq_out.ifr_mtu + (oInteristun ? 0 : 14))), 0, (struct sockaddr *)&sockAddr_out, sizeof(sockAddr_out))) {
                perror("Sending failure");
            } else { transmac_ip_success = true; }*/
            ignoreout=true;
            if (-1 == sendmsg(ipSock_out.fdSock, &msg_header_pktout, 0)) {
                perror("Sending failure:-o");
            } else { transmac_ip_success = true;
            continue; }
            //memset(ghxbuf,0,sizeof(ghxbuf));
            //memset(ghxbuf,0,1514);
            //memcpy(buf,ghybuf,sizeof(MACHeader));
            sockAddrghx.sll_protocol = htons(ETH_P_ALL);
            ghxsiz = 0;
            continue;
        } else if ((((nataddr4host == false) && (((pMAC2.arpHeader.TargetIP[0] & mysubnetmask[0]) == (pMAC.arpHeader.SenderIP[0] & mysubnetmask[0])) && ((pMAC2.arpHeader.TargetIP[1] & mysubnetmask[1]) == (pMAC.arpHeader.SenderIP[1] & mysubnetmask[1])) && ((pMAC2.arpHeader.TargetIP[2] & mysubnetmask[2]) == (pMAC.arpHeader.SenderIP[2] & mysubnetmask[2])) && ((pMAC2.arpHeader.TargetIP[3] & mysubnetmask[3]) == (pMAC.arpHeader.SenderIP[3] & mysubnetmask[3])))) || ((nataddr4host == true) && (((pMAC2.arpHeader.TargetIP[0]) == (pMAC.arpHeader.SenderIP[0])) && ((pMAC2.arpHeader.TargetIP[1]) == (pMAC.arpHeader.SenderIP[1])) && ((pMAC2.arpHeader.TargetIP[2]) == (pMAC.arpHeader.SenderIP[2])) && ((pMAC2.arpHeader.TargetIP[3]) == (pMAC.arpHeader.SenderIP[3]))))) && ((((pMAC2.destMACAddr[0] == pMAC.srcMACAddr[0]) && (pMAC2.destMACAddr[1] == pMAC.srcMACAddr[1]) && (pMAC2.destMACAddr[2] == pMAC.srcMACAddr[2]) && (pMAC2.destMACAddr[3] == pMAC.srcMACAddr[3]) && (pMAC2.destMACAddr[4] == pMAC.srcMACAddr[4]) && (pMAC2.destMACAddr[5] == pMAC.srcMACAddr[5])) || ((pMAC2.destMACAddr[0] & 0x01))) && (sockAddrghx.sll_protocol == htons(ETH_P_ARP)) && (nomeflag == false || ((*(unsigned int*)&myinterfaceip) != (*(unsigned int*)&pMAC2.arpHeader.SenderIP))))){
            memcpy(pMAC_arpin.arpHeader.SenderIP, pMAC2.arpHeader.TargetIP, sizeof(in_addr_t));
            memcpy(pMAC_arpin.destMACAddr, pMAC2.srcMACAddr, sizeof(pMAC.destMACAddr));
            memcpy(pMAC_arpin.arpHeader.TargetMAC, pMAC2.arpHeader.SenderMAC, sizeof(pMAC.arpHeader.TargetMAC));
            memcpy(pMAC_arpin.arpHeader.TargetIP, pMAC2.arpHeader.SenderIP, sizeof(in_addr_t));
            //memcpy(pMAC_arpin.srcMACAddr, pMAC2.destMACAddr, sizeof(pMAC.srcMACAddr));
            //memcpy(pMAC_arpin.arpHeader.SenderMAC, pMAC2.arpHeader.TargetMAC, sizeof(pMAC.arpHeader.SenderMAC));
            if (((pMAC2.arpHeader.SenderIP[0] == rti[0]) && (pMAC2.arpHeader.SenderIP[1] == rti[1]) && (pMAC2.arpHeader.SenderIP[2] == rti[2]) && (pMAC2.arpHeader.SenderIP[3] == rti[3]))) { memcpy(rtm, pMAC2.arpHeader.SenderMAC, sizeof(pMAC2.arpHeader.SenderMAC)); memcpy(pMAC.destMACAddr, rtm, sizeof(pMAC.destMACAddr)); memcpy(pMAC_arpin.destMACAddr, rtm, sizeof(pMAC.destMACAddr)); memcpy(pMAC_arpout.destMACAddr, rtm, sizeof(pMAC.destMACAddr)); memcpy(pMAC.arpHeader.TargetMAC, rtm, sizeof(pMAC.arpHeader.TargetMAC)); memcpy(pMAC_arpin.arpHeader.TargetMAC, rtm, sizeof(pMAC.arpHeader.TargetMAC)); memcpy(pMAC_arpout.arpHeader.TargetMAC, rtm, sizeof(pMAC.arpHeader.TargetMAC)); }
            sockAddr.sll_ifindex = ifindex4in;
            sockAddr_out_arp.sll_ifindex = ifindex4out;
            sockAddrghx.sll_ifindex = ifindex4in;
            sockAddr_out.sll_ifindex = ifindex4out;
            msg_iov_pktin.iov_base = &buf_arpin;
            msg_iov_pktin.iov_len = sizeof(buf_arpin);
            msg_header_pktin.msg_name = &sockAddr;
            msg_header_pktin.msg_namelen = sizeof(sockAddr);
            msg_header_pktin.msg_iov = &msg_iov_pktin;
            msg_header_pktin.msg_iovlen = 1;
            msg_header_pktin.msg_control = NULL;
            msg_header_pktin.msg_controllen = 0;
            msg_header_pktin.msg_flags = 0;
            sockAddr.sll_protocol = htons(ETH_P_ARP);
            /*if (-1 == sendto(ipSock.fdSock, buf_arpin, sizeof(buf_arpin), 0, (struct sockaddr *)&sockAddr, sizeof(sockAddr))) {
                perror("Sending failure");
            } else { transmac_ip_success = true; }*/
            if (-1 == sendmsg(ipSock.fdSock, &msg_header_pktin,0)) {
                perror("Sending failure");
            } else { transmac_ip_success = true;
            continue; }
            sockAddrghx.sll_protocol = htons(ETH_P_ALL);
            //memcpy(buf,ghybuf,sizeof(MACHeader));
            ghxsiz = 0;
            continue;
        }
        if (transmac_ip_success){ goto pMAC3_maniplation_; }
        transmac_ip_success = false;
        //memcpy(buf,ghybuf,sizeof(MACHeader));
        }
        }
        }
            continue;
    } else if (events[cnt_of_epfd].data.fd==ipSock_out.fdSock){
pMAC3_maniplation:
        transmac_ip_success = false;
        if ((events[cnt_of_epfd].data.fd==ipSock_out.fdSock)){
        //if (!FD_ISSET(ipSock_out.fdSock, &fds)){ goto pMAC3_maniplation_; }
        sockAddr_out.sll_family = AF_PACKET;
        sockAddr_out.sll_halen = HW_ADDR_LENGTH;
        sockAddr_out.sll_protocol = htons(ETH_P_ALL);
        if (oInteristun == true){memset(sockAddr_out.sll_addr,0,8);sockAddr_out.sll_halen=0;sockAddr_out.sll_protocol = htons(ETH_P_IP);}
        sockAddr.sll_ifindex = ifindex4in;
        sockAddr_out_arp.sll_ifindex = ifindex4out;
        sockAddrghx.sll_ifindex = ifindex4in;
        sockAddr_out.sll_ifindex = ifindex4out;
        sockAddr_outsiz = sizeof(sockAddr_out);
        /*if (-1 == (ghzsiz = recvfrom(ipSock_out.fdSock, ghzbuf + (oInteristun ? 14 : 0), sizeof(ghzbuf), 0, (struct sockaddr *)&sockAddr_out, (socklen_t*)&sockAddr_outsiz))) {
            perror("Receiveing failure(oInterface)");
        }*/
        msg_iov_pktout.iov_base = (((void*)&ghzbuf) + ((unsigned long long)(oInteristun ? 14 : 0)));
        msg_iov_pktout.iov_len = (sizeof(ghzbuf) - (oInteristun ? 14 : 0));
        msg_header_pktout.msg_name = &sockAddr_out;
        msg_header_pktout.msg_namelen = sockAddr_outsiz;
        msg_header_pktout.msg_iov = &msg_iov_pktout;
        msg_header_pktout.msg_iovlen = 1;
        msg_header_pktout.msg_control = NULL;
        msg_header_pktout.msg_controllen = 0;
        msg_header_pktout.msg_flags = 0;
        if (-1 == (ghzsiz = recvmsg(ipSock_out.fdSock, &msg_header_pktout, 0))) {
            if (iInteristun==false) {perror("Receiveing failure(oInterface)");}
            ghzsiz = ifreq_out.ifr_mtu + 14;
        }
        if (sockAddr_out.sll_pkttype!=PACKET_HOST && sockAddr_out.sll_pkttype!=PACKET_MULTICAST && sockAddr_out.sll_pkttype!=PACKET_BROADCAST && sockAddr_out.sll_pkttype!=PACKET_OTHERHOST){ ghzsiz = 0; goto pMAC3_maniplation_; }
        if (!(sockAddr_out.sll_pkttype!=PACKET_HOST && sockAddr_out.sll_pkttype!=PACKET_MULTICAST && sockAddr_out.sll_pkttype!=PACKET_BROADCAST && sockAddr_out.sll_pkttype!=PACKET_OTHERHOST) && (sockAddr_out.sll_ifindex == ifindex4out)){
        if (oInteristun == true){
            sockAddr_out.sll_protocol == htons(ETH_P_IP);
            memcpy(pIP4MAC3.srcMACAddr, msm, sizeof(pMAC.srcMACAddr));
            memcpy(pIP4MAC3.destMACAddr, mtm, sizeof(pMAC.srcMACAddr));
            pIP4MAC3.upperType = htons(ETH_P_IP);
        }
        sockAddr.sll_ifindex = ifindex4in;
        sockAddr_out_arp.sll_ifindex = ifindex4out;
        sockAddrghx.sll_ifindex = ifindex4in;
        sockAddr_out.sll_ifindex = ifindex4out;
        if (((sockAddr_out.sll_protocol == htons(ETH_P_ARP)) || (sockAddr_out.sll_protocol == htons(ETH_P_IP))) && !((pMAC3.srcMACAddr[0] == mtm[0]) && (pMAC3.srcMACAddr[1] == mtm[1]) && (pMAC3.srcMACAddr[2] == mtm[2]) && (pMAC3.srcMACAddr[3] == mtm[3]) && (pMAC3.srcMACAddr[4] == mtm[4]) && (pMAC3.srcMACAddr[5] == mtm[5]))){
        if ((((pIP4MAC3.ip4Header.SRCIP[0] == ndi_binary[0] && pIP4MAC3.ip4Header.SRCIP[1] == ndi_binary[1] && pIP4MAC3.ip4Header.SRCIP[2] == ndi_binary[2] && pIP4MAC3.ip4Header.SRCIP[3] == ndi_binary[3]) && nataddr4host == true) || ((((pIP4MAC3.ip4Header.SRCIP[0] & mysubnetmask[0]) == (pMAC.arpHeader.SenderIP[0] & mysubnetmask[0])) && ((pIP4MAC3.ip4Header.SRCIP[1] & mysubnetmask[1]) == (pMAC.arpHeader.SenderIP[1] & mysubnetmask[1])) && ((pIP4MAC3.ip4Header.SRCIP[2] & mysubnetmask[2]) == (pMAC.arpHeader.SenderIP[2] & mysubnetmask[2])) && ((pIP4MAC3.ip4Header.SRCIP[3] & mysubnetmask[3]) == (pMAC.arpHeader.SenderIP[3] & mysubnetmask[3]))) && nataddr4host == false) || (isl3promisc == true)) && ((((pMAC3.destMACAddr[0] == mtm[0]) && (pMAC3.destMACAddr[1] == mtm[1]) && (pMAC3.destMACAddr[2] == mtm[2]) && (pMAC3.destMACAddr[3] == mtm[3]) && (pMAC3.destMACAddr[4] == mtm[4]) && (pMAC3.destMACAddr[5] == mtm[5]))) && (sockAddr_out.sll_protocol == htons(ETH_P_IP)) && (nomeflag == false || ((*(unsigned int*)&mti_binary) != (*(unsigned int*)&pIP4MAC3.ip4Header.DSTIP))))){
        //if ((((pIP4MAC3.ip4Header.SRCIP[0] & mysubnetmask[0]) == (pMAC.arpHeader.SenderIP[0] & mysubnetmask[0])) && ((pIP4MAC3.ip4Header.SRCIP[1] & mysubnetmask[1]) == (pMAC.arpHeader.SenderIP[1] & mysubnetmask[1])) && ((pIP4MAC3.ip4Header.SRCIP[2] & mysubnetmask[2]) == (pMAC.arpHeader.SenderIP[2] & mysubnetmask[2])) && ((pIP4MAC3.ip4Header.SRCIP[3] & mysubnetmask[3]) == (pMAC.arpHeader.SenderIP[3] & mysubnetmask[3]))) && ((((pMAC3.destMACAddr[0] == mtm[0]) && (pMAC3.destMACAddr[1] == mtm[1]) && (pMAC3.destMACAddr[2] == mtm[2]) && (pMAC3.destMACAddr[3] == mtm[3]) && (pMAC3.destMACAddr[4] == mtm[4]) && (pMAC3.destMACAddr[5] == mtm[5]))) && (sockAddr_out.sll_protocol == htons(ETH_P_IP)) && (nomeflag == false || ((*(unsigned int*)&mti_binary) != (*(unsigned int*)&pIP4MAC3.ip4Header.DSTIP))))){
        //if ((((pIP4MAC3.ip4Header.SRCIP[0] == nsi_binary[0] && pIP4MAC3.ip4Header.SRCIP[1] == nsi_binary[1] && pIP4MAC3.ip4Header.SRCIP[2] == nsi_binary[2] && pIP4MAC3.ip4Header.SRCIP[3] == nsi_binary[3]) && !(nsi_binary[0]==0 && nsi_binary[1]==0 && nsi_binary[2]==0 && nsi_binary[3]==0)) || ((((pIP4MAC3.ip4Header.SRCIP[0] & mysubnetmask[0]) == (pMAC.arpHeader.SenderIP[0] & mysubnetmask[0])) && ((pIP4MAC3.ip4Header.SRCIP[1] & mysubnetmask[1]) == (pMAC.arpHeader.SenderIP[1] & mysubnetmask[1])) && ((pIP4MAC3.ip4Header.SRCIP[2] & mysubnetmask[2]) == (pMAC.arpHeader.SenderIP[2] & mysubnetmask[2])) && ((pIP4MAC3.ip4Header.SRCIP[3] & mysubnetmask[3]) == (pMAC.arpHeader.SenderIP[3] & mysubnetmask[3]))) && (nsi_binary[0]==0 && nsi_binary[1]==0 && nsi_binary[2]==0 && nsi_binary[3]==0))) && ((((pMAC3.destMACAddr[0] == mtm[0]) && (pMAC3.destMACAddr[1] == mtm[1]) && (pMAC3.destMACAddr[2] == mtm[2]) && (pMAC3.destMACAddr[3] == mtm[3]) && (pMAC3.destMACAddr[4] == mtm[4]) && (pMAC3.destMACAddr[5] == mtm[5]))) && (sockAddr_out.sll_protocol == htons(ETH_P_IP)) && (nomeflag == false || ((*(unsigned int*)&mti_binary) != (*(unsigned int*)&pIP4MAC3.ip4Header.DSTIP))))){
        //if ((!((pIP4MAC3.ip4Header.SRCIP[0]==0 && pIP4MAC3.ip4Header.SRCIP[1]==0 && pIP4MAC3.ip4Header.SRCIP[2]==0 && pIP4MAC3.ip4Header.SRCIP[3]==0) || (pIP4MAC3.ip4Header.SRCIP[0]==255 && pIP4MAC3.ip4Header.SRCIP[1]==255 && pIP4MAC3.ip4Header.SRCIP[2]==255 && pIP4MAC3.ip4Header.SRCIP[3]==255))) && ((((pMAC3.destMACAddr[0] == mtm[0]) && (pMAC3.destMACAddr[1] == mtm[1]) && (pMAC3.destMACAddr[2] == mtm[2]) && (pMAC3.destMACAddr[3] == mtm[3]) && (pMAC3.destMACAddr[4] == mtm[4]) && (pMAC3.destMACAddr[5] == mtm[5]))) && (sockAddr_out.sll_protocol == htons(ETH_P_IP)) && (nomeflag == false || ((*(unsigned int*)&mti_binary) != (*(unsigned int*)&pIP4MAC3.ip4Header.DSTIP))))){
            if (sendonly){ goto pMAC3_maniplation_; }
            //if (unfunctedpart2 == true) { unfunctedpart2 = false; goto pMAC3_maniplation_; }
            //unfunctedpart2 = true;
            //memcpy(buf,ghybuf,sizeof(MACHeader));
            memcpy(pIP4MAC3.srcMACAddr, pMAC.srcMACAddr, sizeof(pMAC.srcMACAddr));
            memcpy(pIP4MAC3.destMACAddr, pMAC.destMACAddr, sizeof(pMAC.srcMACAddr));
            /*for(int cnt=0;cnt<6;cnt++){
                *(char*)(&pIP4MAC3.srcMACAddr)[cnt] = *(char*)(pMAC.srcMACAddr)[cnt];
                *(char*)(&pIP4MAC3.destMACAddr)[cnt] = *(char*)(pMAC.destMACAddr)[cnt];
            }*/
            //pIP4MAC3.ip4Header.TTL--;
            if (nataddr4host == true && (pIP4MAC3.ip4Header.SRCIP[0] == ndi_binary[0] && pIP4MAC3.ip4Header.SRCIP[1] == ndi_binary[1] && pIP4MAC3.ip4Header.SRCIP[2] == ndi_binary[2] && pIP4MAC3.ip4Header.SRCIP[3] == ndi_binary[3]) && (pIP4MAC3.ip4Header.DSTIP[0] == nsi_binary[0] && pIP4MAC3.ip4Header.DSTIP[1] == nsi_binary[1] && pIP4MAC3.ip4Header.DSTIP[2] == nsi_binary[2] && pIP4MAC3.ip4Header.DSTIP[3] == nsi_binary[3])){
                /*for(int cnt=0;cnt<6;cnt++){
                    *(char*)(&pIP4MAC3.srcMACAddr)[cnt] = *(char*)(&mtm)[cnt];
                    *(char*)(&pIP4MAC3.destMACAddr)[cnt] = *(char*)(&msm)[cnt];
                }*/
                memcpy(pIP4MAC3.srcMACAddr, mtm, sizeof(pMAC.srcMACAddr));
                memcpy(pIP4MAC3.destMACAddr, msm, sizeof(pMAC.srcMACAddr));
                //decipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                pIP4MAC3.ip4Header.SRCIP[0] = nsi_binary[0];
                pIP4MAC3.ip4Header.SRCIP[1] = nsi_binary[1];
                pIP4MAC3.ip4Header.SRCIP[2] = nsi_binary[2];
                pIP4MAC3.ip4Header.SRCIP[3] = nsi_binary[3];
                pIP4MAC3.ip4Header.DSTIP[0] = ndi_binary[0];
                pIP4MAC3.ip4Header.DSTIP[1] = ndi_binary[1];
                pIP4MAC3.ip4Header.DSTIP[2] = ndi_binary[2];
                pIP4MAC3.ip4Header.DSTIP[3] = ndi_binary[3];
                //ip4portswap((IP4Header*)&pIP4MAC3.ip4Header);
                calculateipchksum((IP4Header*)&pIP4MAC3.ip4Header);
                //incipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                sockAddr.sll_ifindex = ifindex4in;
                sockAddr_out_arp.sll_ifindex = ifindex4out;
                sockAddrghx.sll_ifindex = ifindex4in;
                sockAddr_out.sll_ifindex = ifindex4out;
                msg_iov_pktin.iov_base = (((void*)&ghzbuf) + ((unsigned long long)(oInteristun ? 14 : 0)));
                msg_iov_pktin.iov_len = (((ghzsiz & 0xFFFF) < (ifreq_out.ifr_mtu + (oInteristun ? 0 : 14))) ? (ghzsiz & 0xFFFF) : (ifreq_out.ifr_mtu + (oInteristun ? 0 : 14)));
                msg_header_pktin.msg_name = &sockAddr_out;
                msg_header_pktin.msg_namelen = sizeof(sockAddr_out);
                msg_header_pktin.msg_iov = &msg_iov_pktin;
                msg_header_pktin.msg_iovlen = 1;
                msg_header_pktin.msg_control = NULL;
                msg_header_pktin.msg_controllen = 0;
                msg_header_pktin.msg_flags = 0;
                /*if (-1 == sendto(ipSock_out.fdSock, ghzbuf + (oInteristun ? 14 : 0), (((ghzsiz & 0xFFFF) < (ifreq_out.ifr_mtu + (oInteristun ? 0 : 14))) ? (ghzsiz & 0xFFFF) : (ifreq_out.ifr_mtu + (oInteristun ? 0 : 14))), 0, (struct sockaddr *)&sockAddr_out, sizeof(sockAddr_out))) {
                    perror("Sending failure");
                } else { transmac_ip_success = true; }*/
                if (-1 == sendmsg(ipSock_out.fdSock, &msg_header_pktin, 0)) {
                    perror("Sending failure:-o");
                } else { transmac_ip_success = true;
                continue; }
                //memset(ghxbuf,0,sizeof(ghxbuf));
                //memset(ghxbuf,0,1514);
                //memcpy(buf,ghybuf,sizeof(MACHeader));
                sockAddrghx.sll_protocol = htons(ETH_P_ALL);
                ghzsiz = 0;
                continue;
            } else {
                if ((((ndp_binary[0] & mysubnetmask[0]) == (pIP4MAC3.ip4Header.SRCIP[0] & mysubnetmask[0])) && ((ndp_binary[1] & mysubnetmask[1]) == (pIP4MAC3.ip4Header.SRCIP[1] & mysubnetmask[1])) && ((ndp_binary[2] & mysubnetmask[2]) == (pIP4MAC3.ip4Header.SRCIP[2] & mysubnetmask[2])) && ((ndp_binary[3] & mysubnetmask[3]) == (pIP4MAC3.ip4Header.SRCIP[3] & mysubnetmask[3])))) {
                    decipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                    pIP4MAC3.ip4Header.SRCIP[0] = (nsp_binary[0] & mysubnetmask[0]) | (pIP4MAC3.ip4Header.SRCIP[0] & ~mysubnetmask[0]);
                    pIP4MAC3.ip4Header.SRCIP[1] = (nsp_binary[1] & mysubnetmask[1]) | (pIP4MAC3.ip4Header.SRCIP[1] & ~mysubnetmask[1]);
                    pIP4MAC3.ip4Header.SRCIP[2] = (nsp_binary[2] & mysubnetmask[2]) | (pIP4MAC3.ip4Header.SRCIP[2] & ~mysubnetmask[2]);
                    pIP4MAC3.ip4Header.SRCIP[3] = (nsp_binary[3] & mysubnetmask[3]) | (pIP4MAC3.ip4Header.SRCIP[3] & ~mysubnetmask[3]);
                    //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                    incipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                } else if ((((nsp_binary[0] & mysubnetmask[0]) == (pIP4MAC3.ip4Header.DSTIP[0] & mysubnetmask[0])) && ((nsp_binary[1] & mysubnetmask[1]) == (pIP4MAC3.ip4Header.DSTIP[1] & mysubnetmask[1])) && ((nsp_binary[2] & mysubnetmask[2]) == (pIP4MAC3.ip4Header.DSTIP[2] & mysubnetmask[2])) && ((nsp_binary[3] & mysubnetmask[3]) == (pIP4MAC3.ip4Header.DSTIP[3] & mysubnetmask[3])))) {
                    decipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                    pIP4MAC3.ip4Header.DSTIP[0] = (ndp_binary[0] & mysubnetmask[0]) | (pIP4MAC3.ip4Header.DSTIP[0] & ~mysubnetmask[0]);
                    pIP4MAC3.ip4Header.DSTIP[1] = (ndp_binary[1] & mysubnetmask[1]) | (pIP4MAC3.ip4Header.DSTIP[1] & ~mysubnetmask[1]);
                    pIP4MAC3.ip4Header.DSTIP[2] = (ndp_binary[2] & mysubnetmask[2]) | (pIP4MAC3.ip4Header.DSTIP[2] & ~mysubnetmask[2]);
                    pIP4MAC3.ip4Header.DSTIP[3] = (ndp_binary[3] & mysubnetmask[3]) | (pIP4MAC3.ip4Header.DSTIP[3] & ~mysubnetmask[3]);
                    //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                    incipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                } else if ((((nsp_binary[0] & mysubnetmask[0]) == (pIP4MAC3.ip4Header.SRCIP[0] & mysubnetmask[0])) && ((nsp_binary[1] & mysubnetmask[1]) == (pIP4MAC3.ip4Header.SRCIP[1] & mysubnetmask[1])) && ((nsp_binary[2] & mysubnetmask[2]) == (pIP4MAC3.ip4Header.SRCIP[2] & mysubnetmask[2])) && ((nsp_binary[3] & mysubnetmask[3]) == (pIP4MAC3.ip4Header.SRCIP[3] & mysubnetmask[3])))) {
                    decipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                    pIP4MAC3.ip4Header.SRCIP[0] = (ndp_binary[0] & mysubnetmask[0]) | (pIP4MAC3.ip4Header.SRCIP[0] & ~mysubnetmask[0]);
                    pIP4MAC3.ip4Header.SRCIP[1] = (ndp_binary[1] & mysubnetmask[1]) | (pIP4MAC3.ip4Header.SRCIP[1] & ~mysubnetmask[1]);
                    pIP4MAC3.ip4Header.SRCIP[2] = (ndp_binary[2] & mysubnetmask[2]) | (pIP4MAC3.ip4Header.SRCIP[2] & ~mysubnetmask[2]);
                    pIP4MAC3.ip4Header.SRCIP[3] = (ndp_binary[3] & mysubnetmask[3]) | (pIP4MAC3.ip4Header.SRCIP[3] & ~mysubnetmask[3]);
                    //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                    incipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                } else if ((((ndp_binary[0] & mysubnetmask[0]) == (pIP4MAC3.ip4Header.DSTIP[0] & mysubnetmask[0])) && ((ndp_binary[1] & mysubnetmask[1]) == (pIP4MAC3.ip4Header.DSTIP[1] & mysubnetmask[1])) && ((ndp_binary[2] & mysubnetmask[2]) == (pIP4MAC3.ip4Header.DSTIP[2] & mysubnetmask[2])) && ((ndp_binary[3] & mysubnetmask[3]) == (pIP4MAC3.ip4Header.DSTIP[3] & mysubnetmask[3])))) {
                    decipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                    pIP4MAC3.ip4Header.DSTIP[0] = (nsp_binary[0] & mysubnetmask[0]) | (pIP4MAC3.ip4Header.DSTIP[0] & ~mysubnetmask[0]);
                    pIP4MAC3.ip4Header.DSTIP[1] = (nsp_binary[1] & mysubnetmask[1]) | (pIP4MAC3.ip4Header.DSTIP[1] & ~mysubnetmask[1]);
                    pIP4MAC3.ip4Header.DSTIP[2] = (nsp_binary[2] & mysubnetmask[2]) | (pIP4MAC3.ip4Header.DSTIP[2] & ~mysubnetmask[2]);
                    pIP4MAC3.ip4Header.DSTIP[3] = (nsp_binary[3] & mysubnetmask[3]) | (pIP4MAC3.ip4Header.DSTIP[3] & ~mysubnetmask[3]);
                    //calculateipchksum((IP4Header*)&pIP4MAC2.ip4Header);
                    incipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                }
                //if (ignoreout==true && (pIP4MAC3.ip4Header.DSTIP[0] == pIP4MAC2.ip4Header.DSTIP[0] && pIP4MAC3.ip4Header.DSTIP[1] == pIP4MAC2.ip4Header.DSTIP[1] && pIP4MAC3.ip4Header.DSTIP[2] == pIP4MAC2.ip4Header.DSTIP[2] && pIP4MAC3.ip4Header.DSTIP[3] == pIP4MAC2.ip4Header.DSTIP[3])){if (ignorecount==1){ignoreout=false; ignorecount=0;}else{ignorecount++;} continue;}
                if (((ndi_binary[0] == pIP4MAC3.ip4Header.SRCIP[0]) && (ndi_binary[1] == pIP4MAC3.ip4Header.SRCIP[1]) && (ndi_binary[2] == pIP4MAC3.ip4Header.SRCIP[2]) && (ndi_binary[3] == pIP4MAC3.ip4Header.SRCIP[3]))) {
                    decipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                    pIP4MAC3.ip4Header.SRCIP[0] = nsi_binary[0];
                    pIP4MAC3.ip4Header.SRCIP[1] = nsi_binary[1];
                    pIP4MAC3.ip4Header.SRCIP[2] = nsi_binary[2];
                    pIP4MAC3.ip4Header.SRCIP[3] = nsi_binary[3];
                    //calculateipchksum((IP4Header*)&pIP4MAC3.ip4Header);
                    if (incdec_ttl!=0){
                        pIP4MAC3.ip4Header.TTL += incdec_ttl;
                    }
                    incipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                } else if (((nsi_binary[0] == pIP4MAC3.ip4Header.DSTIP[0]) && (nsi_binary[1] == pIP4MAC3.ip4Header.DSTIP[1]) && (nsi_binary[2] == pIP4MAC3.ip4Header.DSTIP[2]) && (nsi_binary[3] == pIP4MAC3.ip4Header.DSTIP[3]))) {
                    decipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                    pIP4MAC3.ip4Header.DSTIP[0] = ndi_binary[0];
                    pIP4MAC3.ip4Header.DSTIP[1] = ndi_binary[1];
                    pIP4MAC3.ip4Header.DSTIP[2] = ndi_binary[2];
                    pIP4MAC3.ip4Header.DSTIP[3] = ndi_binary[3];
                    //calculateipchksum((IP4Header*)&pIP4MAC3.ip4Header);
                    if (incdec_ttl!=0){
                        pIP4MAC3.ip4Header.TTL += incdec_ttl;
                    }
                    incipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                } else if (((nsi_binary[0] == pIP4MAC3.ip4Header.SRCIP[0]) && (nsi_binary[1] == pIP4MAC3.ip4Header.SRCIP[1]) && (nsi_binary[2] == pIP4MAC3.ip4Header.SRCIP[2]) && (nsi_binary[3] == pIP4MAC3.ip4Header.SRCIP[3]))) {
                    decipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                    pIP4MAC3.ip4Header.SRCIP[0] = ndi_binary[0];
                    pIP4MAC3.ip4Header.SRCIP[1] = ndi_binary[1];
                    pIP4MAC3.ip4Header.SRCIP[2] = ndi_binary[2];
                    pIP4MAC3.ip4Header.SRCIP[3] = ndi_binary[3];
                    //calculateipchksum((IP4Header*)&pIP4MAC3.ip4Header);
                    if (incdec_ttl!=0){
                        pIP4MAC3.ip4Header.TTL += incdec_ttl;
                    }
                    incipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                } else if (((ndi_binary[0] == pIP4MAC3.ip4Header.DSTIP[0]) && (ndi_binary[1] == pIP4MAC3.ip4Header.DSTIP[1]) && (ndi_binary[2] == pIP4MAC3.ip4Header.DSTIP[2]) && (ndi_binary[3] == pIP4MAC3.ip4Header.DSTIP[3]))) {
                    decipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                    pIP4MAC3.ip4Header.DSTIP[0] = nsi_binary[0];
                    pIP4MAC3.ip4Header.DSTIP[1] = nsi_binary[1];
                    pIP4MAC3.ip4Header.DSTIP[2] = nsi_binary[2];
                    pIP4MAC3.ip4Header.DSTIP[3] = nsi_binary[3];
                    //calculateipchksum((IP4Header*)&pIP4MAC3.ip4Header);
                    if (incdec_ttl!=0){
                        pIP4MAC3.ip4Header.TTL += incdec_ttl;
                    }
                    incipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                } else if (incdec_ttl!=0){
                    decipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                    pIP4MAC3.ip4Header.TTL += incdec_ttl;
                    incipchecksum((IP4Header*)&pIP4MAC3.ip4Header);
                }
                sockAddr.sll_ifindex = ifindex4in;
                sockAddr_out_arp.sll_ifindex = ifindex4out;
                sockAddrghx.sll_ifindex = ifindex4in;
                sockAddr_out.sll_ifindex = ifindex4out;
                msg_iov_pktin.iov_base = (((void*)&ghzbuf) + ((unsigned long long)(iInteristun ? 14 : 0)));
                msg_iov_pktin.iov_len = (((ghzsiz & 0xFFFF) < (ifreq.ifr_mtu + (iInteristun ? 0 : 14))) ? (ghzsiz & 0xFFFF) : (ifreq.ifr_mtu + (iInteristun ? 0 : 14)));
                msg_header_pktin.msg_name = &sockAddr;
                msg_header_pktin.msg_namelen = sizeof(sockAddr);
                msg_header_pktin.msg_iov = &msg_iov_pktin;
                msg_header_pktin.msg_iovlen = 1;
                msg_header_pktin.msg_control = NULL;
                msg_header_pktin.msg_controllen = 0;
                msg_header_pktin.msg_flags = 0;
                sockAddr.sll_protocol = htons(ETH_P_IP);
                hatype_out = sockAddr.sll_hatype; sockAddr.sll_hatype = 0;
                sockAddr.sll_pkttype=0;
                sockAddr.sll_halen=0;
                memset(sockAddr.sll_addr,0,8);
                /*if (-1 == sendto(ipSock.fdSock, ghzbuf + (iInteristun ? 14 : 0), (((ghzsiz & 0xFFFF) < (ifreq.ifr_mtu + (iInteristun ? 0 : 14))) ? (ghzsiz & 0xFFFF) : (ifreq.ifr_mtu + (iInteristun ? 0 : 14))), 0, (struct sockaddr *)&sockAddr, sizeof(sockAddr))) {
                    perror("Sending failure");
                } else { transmac_ip_success = true; }*/
                ignorein=true;
                if (-1 == sendmsg(ipSock.fdSock, &msg_header_pktin, 0)) {
                    perror("Sending failure:-i");
                    fprintf(stdout, "%08X%08X\n%08X%08X\n",((int)(((unsigned long long)msg_iov_pktin.iov_base) >> (32 * 1))),((int)(((unsigned long long)msg_iov_pktin.iov_base) >> (32 * 0))),((int)(((unsigned long long)&ghzbuf) >> (32 * 1))),((int)(((unsigned long long)&ghzbuf) >> (32 * 0))));
                } else { transmac_ip_success = true;
                continue; }
                //memset(ghzbuf,0,sizeof(ghzbuf));
                //memset(ghzbuf,0,1514);
                //memcpy(buf,ghybuf,sizeof(MACHeader));
                sockAddr_out.sll_protocol = htons(ETH_P_ALL);
                ghzsiz = 0;
                continue;
            }
        } else if ((((pMAC3.arpHeader.TargetIP[0]) == (mti_binary[0])) && ((pMAC3.arpHeader.TargetIP[1]) == (mti_binary[1])) && ((pMAC3.arpHeader.TargetIP[2]) == (mti_binary[2])) && ((pMAC3.arpHeader.TargetIP[3]) == (mti_binary[3]))) && ((((pMAC3.destMACAddr[0] == mtm[0]) && (pMAC3.destMACAddr[1] == mtm[1]) && (pMAC3.destMACAddr[2] == mtm[2]) && (pMAC3.destMACAddr[3] == mtm[3]) && (pMAC3.destMACAddr[4] == mtm[4]) && (pMAC3.destMACAddr[5] == mtm[5])) || ((pMAC3.destMACAddr[0] & 0x01))) && (sockAddr_out.sll_protocol == htons(ETH_P_ARP)) && (nomeflag == false || ((*(unsigned int*)&mti_binary) != (*(unsigned int*)&pMAC3.arpHeader.SenderIP))))){
            memcpy(pMAC_arpout.arpHeader.SenderIP, mti_binary, sizeof(in_addr_t));
            memcpy(pMAC_arpout.destMACAddr, pMAC3.srcMACAddr, sizeof(pMAC.destMACAddr));
            memcpy(pMAC_arpout.arpHeader.TargetMAC, pMAC3.arpHeader.SenderMAC, sizeof(pMAC.arpHeader.TargetMAC));
            memcpy(pMAC_arpout.arpHeader.TargetIP, pMAC3.arpHeader.SenderIP, sizeof(in_addr_t));
            memcpy(pMAC_arpout.srcMACAddr, mtm, sizeof(pMAC.srcMACAddr));
            memcpy(pMAC_arpout.arpHeader.SenderMAC, mtm, sizeof(pMAC.arpHeader.SenderMAC));
            memcpy(msm, pMAC3.arpHeader.SenderMAC, sizeof(pMAC.arpHeader.SenderMAC));
            //fprintf(stdout, "MSM updated to %02x-%02x-%02x-%02x-%02x-%02x\n", msm[0], msm[1], msm[2], msm[3], msm[4], msm[5]);
            //usleep(0);
            sockAddr.sll_ifindex = ifindex4in;
            sockAddr_out_arp.sll_ifindex = ifindex4out;
            sockAddrghx.sll_ifindex = ifindex4in;
            sockAddr_out.sll_ifindex = ifindex4out;
            msg_iov_pktout.iov_base = &buf_arpout;
            msg_iov_pktout.iov_len = sizeof(buf_arpout);
            msg_header_pktout.msg_name = &sockAddr_out_arp;
            msg_header_pktout.msg_namelen = sizeof(sockAddr_out_arp);
            msg_header_pktout.msg_iov = &msg_iov_pktout;
            msg_header_pktout.msg_iovlen = 1;
            msg_header_pktout.msg_control = NULL;
            msg_header_pktout.msg_controllen = 0;
            msg_header_pktout.msg_flags = 0;
            sockAddr_out_arp.sll_protocol = htons(ETH_P_ARP);
            /*if (-1 == sendto(ipSock_out.fdSock, buf_arpout, sizeof(buf_arpout), 0, (struct sockaddr *)&sockAddr_out_arp, sizeof(sockAddr_out_arp))) {
                perror("Sending failure");
            } else { transmac_ip_success = true; }*/
            if (-1 == sendmsg(ipSock_out.fdSock, &msg_header_pktout,0)) {
                perror("Sending failure");
            } else { transmac_ip_success = true;
            continue; }
            sockAddr_out.sll_protocol = htons(ETH_P_ALL);
            //memcpy(buf,ghybuf,sizeof(MACHeader));
            ghzsiz = 0;
            continue;
        }
        }
        }
        }
            continue;
    }
        if (transmac_ip_success){ goto pMAC3_maniplation_; }
pMAC3_maniplation_finishsend:
        //memcpy(buf,ghybuf,sizeof(MACHeader));
pMAC3_maniplation_:
        if (transmac_ip_success){ break; }
        count4retry2 = 0;
        sockAddrghx.sll_protocol = htons(ETH_P_ALL);
        sockAddr_out.sll_protocol = htons(ETH_P_ALL);
        break;
        }
        //usleep(1);
        //goto gettingpacket;
        //usleep((rand() % 19) + 2);
        //usleep(0);
        if (enabledthepooling){
            if ((timeofpooling + 1) < time(0)){
                timeofpooling = time(0);
                //memcpy(buf,ghybuf,sizeof(MACHeader));
                sockAddr.sll_ifindex = ifindex4in;
                sockAddr_out_arp.sll_ifindex = ifindex4out;
                sockAddrghx.sll_ifindex = ifindex4in;
                sockAddr_out.sll_ifindex = ifindex4out;
                if (-1 == sendto(ipSock.fdSock, buf, sizeof(buf), 0, (struct sockaddr *)&sockAddr, sizeof(sockAddr))) {
                    perror("Sending failure");
                } else { transmac_ip_success = true; }
            }
        }
        if (transmac_ip_success) {
            if (!quite) {
                fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x "
                                "%02x:%02x:%02x:%02x:%02x:%02x %04x 42: arp reply %d.%d.%d.%d is-at "
                                "%02x:%02x:%02x:%02x:%02x:%02x %d.%d.%d.%d\n", pMAC.arpHeader.SenderMAC[0], pMAC.arpHeader.SenderMAC[1], pMAC.arpHeader.SenderMAC[2], pMAC.arpHeader.SenderMAC[3], pMAC.arpHeader.SenderMAC[4], pMAC.arpHeader.SenderMAC[5],
                        pMAC.arpHeader.TargetMAC[0], pMAC.arpHeader.TargetMAC[1], pMAC.arpHeader.TargetMAC[2], pMAC.arpHeader.TargetMAC[3], pMAC.arpHeader.TargetMAC[4], pMAC.arpHeader.TargetMAC[5], (((pMAC3.upperType<<(8*1))&0xFF00) | ((pMAC3.upperType>>(8*1))&0x00FF)), pMAC.arpHeader.SenderIP[0], pMAC.arpHeader.SenderIP[1], pMAC.arpHeader.SenderIP[2], pMAC.arpHeader.SenderIP[3],
                        pMAC.arpHeader.SenderMAC[0], pMAC.arpHeader.SenderMAC[1], pMAC.arpHeader.SenderMAC[2], pMAC.arpHeader.SenderMAC[3], pMAC.arpHeader.SenderMAC[4], pMAC.arpHeader.SenderMAC[5], pMAC.arpHeader.TargetIP[0], pMAC.arpHeader.TargetIP[1], pMAC.arpHeader.TargetIP[2], pMAC.arpHeader.TargetIP[3]);
            }
        }
        //memcpy(buf,ghybuf,sizeof(MACHeader));
        if (iInterval) { sleep(iInterval); }
        //sleep(iInterval);
        //usleep(iInterval);
    }

    return 0;
}

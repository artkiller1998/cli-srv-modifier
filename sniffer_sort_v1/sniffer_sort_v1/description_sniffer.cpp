#include "pcap.h"
#include "stdint.h"

/* 4 bytes IP address  ��������� ���������� 4-�� �������� ������ ������*/		//����� TYPEDEF?
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct mac_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;



typedef struct mac_header{
	mac_address dmac;
	mac_address smac;
	u_int etype; //EtherType - help to recognize Arp or Ip header.
}mac_header;

typedef struct arp_header{
	u_short htype; //Hardware type(HTYPE)������ ��������� �������� �������� ������ ����� ���� �����, ������� �������� � ���� ����.��������, Ethernet ����� ����� 0x0001.
	u_short ptype; //Protocol type(PTYPE)��� �������� ���������.��������, ��� IPv4 ����� �������� 0x0800.
	u_char hlen; //Hardware length(HLEN)����� ����������� ������ � ������.������ Ethernet ����� ����� 6 ����(0x06).
	u_char plen; //Protocol length(PLEN)����� ����������� ������ � ������.IPv4 ������ ����� ����� 4 �����(0x04).
	u_short oper; //Operation.��� �������� ����������� : 0x0001 � ������ ������� � 0x0002 � ������ ������.
	mac_address smac; //Sender hardware address(SHA)���������� ����� �����������.
	ip_address saddr; //Sender protocol address(SPA)���������� ����� �����������.
	mac_address dmac; //Target hardware address(THA)���������� ����� ����������.���� ����� ��� �������.
	ip_address daddr; //Target protocol address(TPA)���������� ����� ����������
}arp_header;






/* IPv4 header			���� ��������� ���� ������*/
typedef struct ip_header{
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short len;           // Total length 
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

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main()
{
	pcap_if_t *alldevs; //������� � ������ �����������
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle; //if not NULL, a pointer to the next element in the list; NULL for the last element of the list
	char errbuf[PCAP_ERRBUF_SIZE]; //������, ������������ ��� ��������� ������, ����������� ������ 
	u_int netmask; //unsigned int
	char packet_filter[] = ""; //?
	struct bpf_program fcode; //https://xakep.ru/2002/10/07/16494/

	/* Retrieve the device list  ��������� ������ ��������� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) //  PCAP_SRC_IF_STRING ���������� ��� ���������
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1); //������ 1?
	}

	/* Print the list  ������� ������ */
	for (d = alldevs; d; d = d->next) // ������ ����������� ���������� pcap_findalldevs, ������� � ���� �� ������ �����
	{
		printf("%d. %s", ++i, d->name); //������� ����� � ������ ��������
		if (d->description)				//���� ���� �������� ���������� ��� ���������
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)				//����� 0 ��������� => ������� ������
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);			//������ ������� ���������
	scanf_s("%d", &inum);										// ��������� ��� � ����������

	if (inum < 1 || inum > i)									//���� �������������� ���������
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);								//����������� ���������� ������ ����������� pcap_findalldevs
		return -1;
	}

	/* Jump to the selected adapter ����������� ��������� �� ��������� �������*/
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the adapter ��������� �������������(�����) �������� ��� ������� / �������� �������.*/
	if ((adhandle = pcap_open(d->name,  // name of the device
		65536,     // portion of the packet to capture.  ����� ������, ������� ������ ���� �������� 
		// 65536 grants that the whole packet will be captured on all the MACs. 65536 ����������� ��� ���� ����� ���������� ��� ������ MAC
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode ? 
		1000,      // read timeout	?
		NULL,      // remote authentication	 ?	
		errbuf     // error buffer	?
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");	//������� �� ������������� ��������. �������� ������ ���������
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. ��������� ����� �������� ������ ��������.���� �� �������� - ������ */
	if (pcap_datalink(adhandle) != DLT_EN10MB) 
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface  ������ ����� ����*/
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network  ���� �� ����� �� �� ��������� ����� �(255.255.255.0)*/
		netmask = 0xffffff;


	//compile the filter ��������� ������ 
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)		//���� �� (������ ��������� , �� ������) �����
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter �������������
	if (pcap_setfilter(adhandle, &fcode)<0)				//���� �� ��� �� �����
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);			//��� ������� ���������� ������� ��������. 

	/* At this point, we don't need any more the device list. Free it ������ ���� �� �����. ��������� ���*/
	pcap_freealldevs(alldevs);

	/* start the capture �������� ������� 
	��� pcap_loop () ����� �� pcap_dispatch (), �� ����������� ����, 
	��� �� ���������� ��������� ������ �� ��� ���, ���� �� ����� ���������� ������ cnt ��� ��������� ������*/
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet    ������� ��������� ������ ���������� � libpcap ��� ������� ��������� ������*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) //unsigned, ������ ����� � ����� ����� ����������� � ����� �������������� ���������. 																					
{		
	//��� ������ �������� ��������� ���������� ��� ��������� ����������� ������.
	struct tm ltime;	//?
	char timestr[16];	//������ �� 16 ��������
	ip_header *ih;		//������� ��������� ��������� IP
	mac_header *mh;
	udp_header *uh;		////������� ��������� ��������� UDP
	arp_header *ah;
	u_int ip_len;		//unsigned ����� ip
	u_int udp_len;
	u_short sport, dport; //unsigned UDP source port,destination port
	time_t local_tv_sec; //����� �������

	/*
	* Unused variable		???
	*/
	(VOID)(param);

	/* convert the timestamp to readable format  ����������� ��������� ����� � ��������� ������ %H:%M:%S*/
	local_tv_sec = header->ts.tv_sec;			//����� ����� �� �������������� ���������
	localtime_s(&ltime, &local_tv_sec);			
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);	//����� ����� � �������

	/* print timestamp and length of the packet  ������� ����� ������� � ����� ������*/

	
	mh = (mac_header *)(pkt_data);
	/* retireve the position of the ip header */		//������� ��������� ��������� �� 14 ��������(����� ��������� MAC) IP-��������� ���������� ����� ����� ��������� MAC.
	ih = (ip_header *)(pkt_data +						//�� �������� IP-����� ��������� � ����� ���������� �� IP-���������.
		14); //length of ethernet header
	ah = (arp_header *)(pkt_data +
		14);

	/* retireve the position of the udp header */		//����� UDP Header
	ip_len = (ih->ver_ihl & 0xf) * 4;					//���������� ��������� UDP ������� �������, ������ ��� ��������� IP �� ����� ������������� �����.
	uh = (udp_header *)((u_char*)ih + ip_len);			//������� �� ���������� ���� ����� ��������� IP, ����� ������ ��� ������.
														//��� ������ �� ������ ������������ ��������� UDP, �� ��������� ����� ��������� � ����������.

	/* convert from network byte order to host byte order �������������� big-endian � �������*/
	udp_len = ntohs(uh->len);
	sport = ntohs(uh->sport); //������������ 16-������ ����������� �������� �� ���������� ������� ������ � �������
	dport = ntohs(uh->dport);

	/* print ip addresses and udp ports ��������� 4 ����� IP ����� ���������, ����� UDP ���������(����?). 4 ����� � UDP �����������(�� ����?)*/

	printf("\n\n-------------BEGIN--------------------------------------------------------------");
	printf("Time of receiving packet: %s. Time stamp:%.6d \n", timestr, header->ts.tv_usec);

	printf("\nProtocol type: Ethernet\n");
	printf("SMAC:%02X:%02X:%02X:%02X:%02X:%02X -> DMAC:%02X:%02X:%02X:%02X:%02X:%02X\n",
		mh->smac.byte1,
		mh->smac.byte2,
		mh->smac.byte3,
		mh->smac.byte4,
		mh->smac.byte5,
		mh->smac.byte6,

		mh->dmac.byte1,
		mh->dmac.byte2,
		mh->dmac.byte3,
		mh->dmac.byte4,
		mh->dmac.byte5,
		mh->dmac.byte6);
	printf("Length: %d\nEthertype 0X%X\n\n", header->len, ntohs(mh->etype));

	switch (ntohs(mh->etype))
	{
	case(0X800):
	{
		printf("\nProtocol type: IP \n");
		printf("SIP:%d.%d.%d.%d -> DIP:%d.%d.%d.%d\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,

			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4);
		printf("Length: %d\n", ip_len);
		if (ih->proto == 17)
		{
			printf("\nProtocol type: UDP\n");
			printf("SP:%d -> DP:%d\n",
				sport,
				dport);
			printf("Length: %d\n\n\n\n", udp_len);
		}
		break;
	}
	case(0X806) :
	{
		printf("\nProtocol type: ARP - %s", ntohs(ah->oper) == 0x0001 ? "REQEST\n" : "ANSWER\n");
		printf("SIP:%d.%d.%d.%d -> DIP:%d.%d.%d.%d\n",
			ah->saddr.byte1,
			ah->saddr.byte2,
			ah->saddr.byte3,
			ah->saddr.byte4,

			ah->daddr.byte1,
			ah->daddr.byte2,
			ah->daddr.byte3,
			ah->daddr.byte4);
		printf("Length logic adress(bytes): %d\n", ah->plen);
		printf("Length hardware adress(bytes): %d\n\n", ah->hlen);
		break;
	}
	default:
		break;
	}
	printf("--------------END---------------------------------------------------------------\n\n");
}
#include <thread>
#include "pcap.h"
#include "stdint.h"
#include <atomic>
#include <map>
#include <mutex>
#include <ctime>
#include <queue>

typedef struct mac_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;

	bool  operator==(const mac_address &o)const;
	bool  operator<(const mac_address &o)const;
	//void print_sw_table();
}mac_address;

typedef struct mac_header{
	mac_address dmac;
	mac_address smac;
	u_int etype; //EtherType - help to recognize Arp or Ip header.
}mac_header;

std::atomic_bool thr_err = ATOMIC_VAR_INIT(false);
std::mutex lock_mutex;
std::map<mac_address, int> sw_table;
std::queue<mac_address> sw_queue;
std::map<mac_address, int>::iterator it;
int timeout = 20;
mac_address iface1_mac;
mac_address iface2_mac;
int count_rm_records = 0;

void print_sw_table(){
	for (it = sw_table.begin(); it != sw_table.end(); it++)
	{
		printf("%02X:%02X:%02X:%02X:%02X:%02X				%d\n", it->first.byte1,
																   it->first.byte2,
																   it->first.byte3, 
																   it->first.byte4, 
																   it->first.byte5, 
																   it->first.byte6, 
																   it->second);
	}
	
}

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

void iface1_thr(pcap_if_t *d, pcap_t *adhandle, u_int netmask, struct bpf_program fcode, char *packet_filter)
{
	char *errbuf = "";
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
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
	}

	/* Check the link layer. We support only Ethernet for simplicity. ��������� ����� �������� ������ ��������.���� �� �������� - ������ */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
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
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
	}

	//set the filter �������������
	if (pcap_setfilter(adhandle, &fcode)<0)				//���� �� ��� �� �����
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
	}

	printf("\nlistening on %s...\n", d->description);			//��� ������� ���������� ������� ��������. 

	/* At this point, we don't need any more the device list. Free it ������ ���� �� �����. ��������� ���*/
	//pcap_freealldevs(alldevs);
	



	/* start the capture �������� �������
	��� pcap_loop () ����� �� pcap_dispatch (), �� ����������� ����,
	��� �� ���������� ��������� ������ �� ��� ���, ���� �� ����� ���������� ������ cnt ��� ��������� ������*/
	pcap_loop(adhandle, 0, packet_handler, (u_char *)"1");
}

void iface2_thr(pcap_if_t *d, pcap_t *adhandle, u_int netmask, struct bpf_program fcode, char *packet_filter)
//{}
{
	char *errbuf = "";
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
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
	}

	/* Check the link layer. We support only Ethernet for simplicity. ��������� ����� �������� ������ ��������.���� �� �������� - ������ */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
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
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
	}

	//set the filter �������������
	if (pcap_setfilter(adhandle, &fcode)<0)				//���� �� ��� �� �����
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
	}

	printf("\nlistening on %s...\n", d->description);			//��� ������� ���������� ������� ��������. 

	/* At this point, we don't need any more the device list. Free it ������ ���� �� �����. ��������� ���*/
	//pcap_freealldevs(alldevs);

	/* start the capture �������� �������
	��� pcap_loop () ����� �� pcap_dispatch (), �� ����������� ����,
	��� �� ���������� ��������� ������ �� ��� ���, ���� �� ����� ���������� ������ cnt ��� ��������� ������*/
	pcap_loop(adhandle, 0, packet_handler, (u_char *)"2");
}

void counter_remover()
{
	while (1)
	{
		Sleep(timeout * 1000);
		//printf("now tmo = %d", timeout);
		if (!sw_table.empty())
		{
			//printf("del ");
			/*printf("%02X:%02X:%02X:%02X:%02X:%02X	\n", sw_queue.front().byte1,
				sw_queue.front().byte2,
				sw_queue.front().byte3,
				sw_queue.front().byte4,
				sw_queue.front().byte5,
				sw_queue.front().byte6);*/
			sw_table.erase(sw_queue.front());
			sw_queue.pop();
		}
	}
	/*
	lock_mutex.lock();
	while (1)
	{
		
		printf("\ntime %d timeout %d     %d \n", time(NULL), timeout, (time(NULL) % timeout));
		if ((time(NULL) % timeout) == 0)
		{
			count_rm_records++;
			printf("\ncrr %d \n", count_rm_records);
			Sleep(1000);
		}

		while (count_rm_records != 0)
		{
			if (sw_table.empty())
			{
				printf("\nclear %d \n", count_rm_records);
				count_rm_records = 0;
				break;
			}
			sw_table.erase(sw_queue.front());
			sw_queue.pop();
			count_rm_records--;
			Sleep(1000);
		}
	}
	lock_mutex.unlock();*/
}

int main()
{
	pcap_if_t *alldevs; //������� � ������ �����������
	pcap_if_t *d;
	char ch = 'a';
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

	iface1_mac.byte1 = '00';
	iface1_mac.byte2 = '50';
	iface1_mac.byte3 = '56';
	iface1_mac.byte4 = '3C';
	iface1_mac.byte5 = 'BE';
	iface1_mac.byte6 = '93';

	iface2_mac.byte1 = '00';
	iface2_mac.byte2 = '50';
	iface2_mac.byte3 = '56';
	iface2_mac.byte4 = '26';
	iface2_mac.byte5 = 'F8';
	iface2_mac.byte6 = 'AE';


	std::thread thr_3(counter_remover);
	/* Jump to the selected adapter ����������� ��������� �� ��������� �������*/
	d = alldevs;																//��� ����� ������ 1 ����� �������� CD.. �������� ������� �������
	std::thread thr_2(iface2_thr, d, adhandle, netmask, fcode, packet_filter);
	d = d->next;
	std::thread thr_1(iface1_thr, d, adhandle, netmask, fcode, packet_filter);

	while (ch != 'q')
	{
		system("cls");
		printf("Press any key\
			\n1.get switch table\
			\n2.set record timeout\
			\nq - to exit\n");
		switch (ch)
		{
		case '1':
			print_sw_table();
			system("PAUSE");
			break;
		case '2':
			printf("Input record timeout in secs:\n");
			scanf("%d", &timeout);
			break;
		case 'q':
			ch = 'q';
			thr_err = ATOMIC_VAR_INIT(true);
			continue;
		default:
			break;
		}
		ch = getchar();
	}
	
	thr_1.join();
	thr_2.join();
	thr_3.join();
	pcap_freealldevs(alldevs);
	return 0;
}



/* Callback function invoked by libpcap for every incoming packet    ������� ��������� ������ ���������� � libpcap ��� ������� ��������� ������*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) //unsigned, ������ ����� � ����� ����� ����������� � ����� �������������� ���������. 																					
{
	mac_header *mh;
	mh = (mac_header *)(pkt_data);

	lock_mutex.lock();
		
	if (sw_table.find(mh->smac) == sw_table.end())
		sw_queue.push(mh->smac);			//����� ������� ����� ������� � ��� �������� ��� ��������. ������� ���� ������� � ������� ���������� �������
	sw_table.insert(std::pair<mac_address, int>((mac_address)mh->smac, atoi((const char *)param)));
	it = sw_table.find(mh->dmac);

	if ((it != sw_table.end()) && (it->second != atoi((const char *)param)))
	{
		printf("translate to other iface");
		switch (atoi((const char *)param))
		{
		case 1:
			mh->dmac = iface2_mac;
			break;
		case 2:
			mh->dmac = iface2_mac;
			break;
		default:
			mh->dmac = mh->smac;
			break;
		}
	}
			
	lock_mutex.unlock();
}

bool mac_address:: operator==(const mac_address &o)const {
	return byte1 == o.byte1 || byte1 == o.byte1 && byte2 == o.byte2;
}

bool mac_address:: operator<(const mac_address &o)const {
	return byte1 < o.byte1 || byte1 == o.byte1 && byte2 < o.byte2 || byte1 == o.byte1 && byte2 == o.byte2 && byte3 < o.byte3
		|| byte1 == o.byte1 && byte2 == o.byte2 && byte3 == o.byte3 && byte4 < o.byte4
		|| byte1 == o.byte1 && byte2 == o.byte2 && byte3 == o.byte3 && byte4 == o.byte4 && byte5 < o.byte5
		|| byte1 == o.byte1 && byte2 == o.byte2 && byte3 == o.byte3 && byte4 == o.byte4 && byte5 == o.byte5 && byte6 < o.byte6;
}
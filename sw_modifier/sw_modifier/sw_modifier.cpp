#include <thread>
#include "pcap.h"
#include "stdint.h"
#include <atomic>
#include <map>
#include <mutex>
#include <ctime>
#include <queue>
#include <set>
//#include <fstream>

#define TIMEOUT_SW_TABLE 2

struct tcp_header{  // 20 bytes : default
	u_short sport;      //Source port
	u_short dport;      //Destination port
	u_long seqno;       //Sequence no
	u_long ackno;       //Ack no
	u_char offset;      //Higher level 4 bit indicates data offset
	u_char flag;        //Message flag: FIN - 0x01, SYN - 0x02, RST - 0x04, PUSH- 0x08, ACK- 0x10, URG- 0x20, ACE- 0x40, CWR- 0x80
	u_short win;
	u_short checksum;
	u_short uptr;
};

typedef struct mac_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;

	bool  operator==(const mac_address &o)const;
	bool  operator<(const mac_address &o)const;
}mac_address;

/* 4 bytes IP address  Структура обохначает 4-ех байтовый формат адреса*/		//зачем TYPEDEF?
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;

	bool  operator==(const ip_address &o)const;
}ip_address;


typedef struct arp_header{
	u_short htype; //Hardware type(HTYPE)Каждый канальный протокол передачи данных имеет свой номер, который хранится в этом поле.Например, Ethernet имеет номер 0x0001.
	u_short ptype; //Protocol type(PTYPE)Код сетевого протокола.Например, для IPv4 будет записано 0x0800.
	u_char hlen; //Hardware length(HLEN)Длина физического адреса в байтах.Адреса Ethernet имеют длину 6 байт(0x06).
	u_char plen; //Protocol length(PLEN)Длина логического адреса в байтах.IPv4 адреса имеют длину 4 байта(0x04).
	u_short oper; //Operation.Код операции отправителя : 0x0001 в случае запроса и 0x0002 в случае ответа.
	mac_address smac; //Sender hardware address(SHA)Физический адрес отправителя.
	ip_address saddr; //Sender protocol address(SPA)Логический адрес отправителя.
	mac_address dmac; //Target hardware address(THA)Физический адрес получателя.Поле пусто при запросе.
	ip_address daddr; //Target protocol address(TPA)Логический адрес получателя
}arp_header;

/* IPv4 header			Поля заголовка айпи адреса*/
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

typedef struct mac_header{
	mac_address dmac;
	mac_address smac;
	u_int etype; //EtherType - help to recognize Arp or Ip header.
}mac_header;

std::atomic_bool flag_exit = ATOMIC_VAR_INIT(false);
bool flag_send = true;
bool disallow_b_d = false;
bool disallow_except_b_c = false;
bool start_pcap_disallow = false;
bool start_pcap_allow = false;

char fname_disallowed[30] = "disallowed_tempfile.pcap";
char fname_allowed[30] = "allowed_tempfile.pcap";

std::mutex lock_mutex;
std::map<mac_address, int> sw_table;
std::queue<mac_address> sw_queue;
std::map<mac_address, int>::iterator it;
std::map<mac_address, int>::iterator it_s;
int timeout = 120;
pcap_t *iface1;
pcap_t *iface2;
pcap_dumper_t *dfile_allow;
pcap_dumper_t *dfile_disallow;

//std::ofstream fout_allowed;
//std::ofstream fout_disallowed;

ip_address a_ip;
ip_address b_ip;
ip_address c_ip;
ip_address d_ip;

void print_sw_table(){
	for (it = sw_table.begin(); it != sw_table.end(); it++) {
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
	/* Open the adapter Открывает универсальный(общий) источник для захвата / передачи трафика.*/
	if ((adhandle = pcap_open(d->name,  // name of the device
		65536,     // portion of the packet to capture.  длина пакета, который должен быть сохранен 
		// 65536 grants that the whole packet will be captured on all the MACs. 65536 гарантирует что весь пакет сохранится для любого MAC
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode ? 
		1000,      // read timeout	?
		NULL,      // remote authentication	 ?	
		errbuf     // error buffer	?
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");	//адаптер не поддерживаеся ВинПикап. Очистить список устройств
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		flag_exit = ATOMIC_VAR_INIT(true);
	}

	/* Check the link layer. We support only Ethernet for simplicity. ПроверЯет канал передачи данных адаптера.Если не интернет - ошибка */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		flag_exit = ATOMIC_VAR_INIT(true);
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface  узнает маску сети*/
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network  если не узнал то по умолчанию класс С(255.255.255.0)*/
		netmask = 0xffffff;

	//compile the filter собрираем фильтр 
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)		//если ош (плохие параметры , мб массив) освоб
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		flag_exit = ATOMIC_VAR_INIT(true);
	}

	//set the filter устанавливаем
	if (pcap_setfilter(adhandle, &fcode)<0)				//если не уст ош освоб
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		flag_exit = ATOMIC_VAR_INIT(true);
	}

	printf("\nlistening on %s...\n", d->description);			//при наличии интерфейса выведет описание. 

	iface1 = adhandle;

	//printf("\nEnter filename ('example.txt')\n");
	//scanf("%s", fname_disallowed);
	dfile_disallow = pcap_dump_open(adhandle, "disallowed_tempfile.pcap");
	
	if (dfile_disallow == NULL)
	{
		fprintf(stderr, "\nError opening output file\n");
	}

	/* start the capture начинаем слушать
	луп pcap_loop () похож на pcap_dispatch (), за исключением того,
	что он продолжает считывать пакеты до тех пор, пока не будут обработаны пакеты cnt или возникнет ошибка*/
	pcap_loop(adhandle, 0, packet_handler, (u_char *)"1");
}

void iface2_thr(pcap_if_t *d, pcap_t *adhandle, u_int netmask, struct bpf_program fcode, char *packet_filter)
{
	char *errbuf = "";
	/* Open the adapter Открывает универсальный(общий) источник для захвата / передачи трафика.*/
	if ((adhandle = pcap_open(d->name,  // name of the device
		65536,     // portion of the packet to capture.  длина пакета, который должен быть сохранен 
		// 65536 grants that the whole packet will be captured on all the MACs. 65536 гарантирует что весь пакет сохранится для любого MAC
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode ? 
		1000,      // read timeout	?
		NULL,      // remote authentication	 ?	
		errbuf     // error buffer	?
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");	//адаптер не поддерживаеся ВинПикап. Очистить список устройств
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		flag_exit = ATOMIC_VAR_INIT(true);
	}

	/* Check the link layer. We support only Ethernet for simplicity. ПроверЯет канал передачи данных адаптера.Если не интернет - ошибка */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		flag_exit = ATOMIC_VAR_INIT(true);
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface  узнает маску сети*/
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network  если не узнал то по умолчанию класс С(255.255.255.0)*/
		netmask = 0xffffff;


	//compile the filter собрираем фильтр 
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)		//если ош (плохие параметры , мб массив) освоб
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		flag_exit = ATOMIC_VAR_INIT(true);
	}

	//set the filter устанавливаем
	if (pcap_setfilter(adhandle, &fcode)<0)				//если не уст ош освоб
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		flag_exit = ATOMIC_VAR_INIT(true);
	}

	printf("\nlistening on %s...\n", d->description);			//при наличии интерфейса выведет описание. 

	/* At this point, we don't need any more the device list. Free it Список устр не нужен. Освободим его*/
	//pcap_freealldevs(alldevs);
	iface2 = adhandle;

	dfile_allow = pcap_dump_open(adhandle, "allowed_tempfile.pcap");
	if (dfile_allow == NULL)
	{
		fprintf(stderr, "\nError opening output file\n");
	}
	/* start the capture начинаем слушать
	луп pcap_loop () похож на pcap_dispatch (), за исключением того,
	что он продолжает считывать пакеты до тех пор, пока не будут обработаны пакеты cnt или возникнет ошибка*/
	pcap_loop(adhandle, 0, packet_handler, (u_char *)"2");
}

void counter_remover()
{
	while (!flag_exit)
	{
		Sleep(TIMEOUT_SW_TABLE * 1000);
		if (!sw_table.empty())
		{
			sw_table.erase(sw_queue.front());
			sw_queue.pop();
		}
	}
}

int main()
{
	pcap_if_t *alldevs; //элемент в списке интерфейсов
	pcap_if_t *d;
	char ch = 'a';
	int i = 0;
	pcap_t *adhandle; //if not NULL, a pointer to the next element in the list; NULL for the last element of the list
	char errbuf[PCAP_ERRBUF_SIZE]; //Размер, используемый при выделении буфера, содержащего ошибки 
	u_int netmask; //unsigned int
	char packet_filter[] = ""; //?
	struct bpf_program fcode; //https://xakep.ru/2002/10/07/16494/

	/* Retrieve the device list  Получение списка устройств */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) //  PCAP_SRC_IF_STRING определяет тип источника
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1); //почему 1?
	}

	/* Print the list  Вывести список */
	for (d = alldevs; d; d = d->next) // список интерфейсов выделенный pcap_findalldevs, переход к след по методу некст
	{
		printf("%d. %s", ++i, d->name); //вывести инекс и строку названия
		if (d->description)				//если есть описание интерфейса оно выводится
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)				//нашло 0 устройств => выводит ошибку
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	//set IP addresses
	// A 192.168.33.13
	a_ip.byte1 = 192;
	a_ip.byte2 = 168;
	a_ip.byte3 = 33;
	a_ip.byte4 = 13;
	// B 192.168.33.26
	b_ip.byte1 = 192;
	b_ip.byte2 = 168;
	b_ip.byte3 = 33;
	b_ip.byte4 = 26;
	// C 192.168.33.39
	c_ip.byte1 = 192;
	c_ip.byte2 = 168;
	c_ip.byte3 = 33;
	c_ip.byte4 = 39;
	// D 192.168.33.52
	d_ip.byte1 = 192;
	d_ip.byte2 = 168;
	d_ip.byte3 = 33;
	d_ip.byte4 = 52;

	char fname_disallowed[30] = "";
	char fname_allowed[30] = "";

	std::thread thr_3(counter_remover);
	/* Jump to the selected adapter переместить указатель на выбранный адаптер*/
	d = alldevs;																//тут важно интерф 1 соотв сегменту CD.. поменяем функции местами
	std::thread thr_2(iface2_thr, d, adhandle, netmask, fcode, packet_filter);
	d = d->next;
	std::thread thr_1(iface1_thr, d, adhandle, netmask, fcode, packet_filter);

	while (ch != 'q')
	{
		system("cls");
		printf("Press any key\
			\n1.Modify by IP addr and port number from 'A -> C' to 'B -> C'\
			2.Disallow ICMP 'B -> D'\
			\n3.Allow TCP 'B -> C' only\
			\n4.Capture PCAP file disallowed trafic\
			\n5.Capture PCAP file allowed trafic\
			\nq - to exit\n");
		switch (ch)
		{
		case '1':
			system("PAUSE");
			break;
		case '2':
			disallow_b_d = disallow_b_d ? false : true;
			printf("Blocking PING transmission from B to D now is: %s\n", disallow_b_d ? "Enable" : "Disable");
			system("PAUSE");
			break;
		case '3':
			disallow_except_b_c = disallow_except_b_c ? false : true;
			printf("Blocking all TCP transmission (except B and C) now is: %s\n", disallow_except_b_c ? "Enable" : "Disable");
			system("PAUSE");
			break;
		case '4':
			start_pcap_disallow = start_pcap_disallow ? false : true;
			if (start_pcap_disallow)
			{
				printf("\nEnter filename ('example.pcap')\n");
				scanf("%s", fname_disallowed);
				printf("Starting the capture. Select this menu item again to stop the capture\n");
			}
			printf("Capture in file '%s' now is: %s\n", fname_disallowed, start_pcap_disallow ? "Enable" : "Disable");
			system("PAUSE");
			break;

		case '5':
			start_pcap_allow = start_pcap_allow ? false : true;
			if (start_pcap_allow)
			{
				printf("\nEnter filename ('example.pcap')\n");
				scanf("%s", fname_allowed);
				printf("Starting the capture. Select this menu item again to stop the capture\n");
			}
			printf("Capture in file '%s' now is: %s\n", fname_allowed, start_pcap_allow ? "Enable" : "Disable");
			system("PAUSE");
			break;
		case 'q':
			ch = 'q';
			flag_exit = ATOMIC_VAR_INIT(true);
			continue;
		default:
			break;
		}
		ch = getchar();
	}
	
	thr_1.detach();
	thr_2.detach();
	thr_3.detach();
	pcap_freealldevs(alldevs);

	pcap_dump_close(dfile_allow);
	pcap_dump_close(dfile_disallow);
	rename("disallowed_tempfile.pcap", fname_disallowed);
	rename("allowed_tempfile.pcap", fname_allowed);

	
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet    Функция обратного вызова вызывается в libpcap для каждого входящего пакета*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) //unsigned, Каждый пакет в файле дампа добавляется к этому универсальному заголовку. 																					
{
	if (flag_exit)
	{
		return;
	}
	//Это решает проблему различных заголовков для различных интерфейсов пакета.
	struct tm ltime;	//?
	char timestr[16];	//массив на 16 символов
	ip_header *ih;		//элемент структуры Заголовок IP
	mac_header *mh;
	udp_header *uh;		////элемент структуры Заголовок UDP
	arp_header *ah;
	tcp_header *th;		////элемент структуры Заголовок TCP
	u_int ip_len;		//unsigned Длина ip
	u_int udp_len;
	u_short udp_sport, udp_dport; //unsigned UDP source port,destination port
	u_short tcp_sport, tcp_dport;
	time_t local_tv_sec; //метка времени

	lock_mutex.lock();

	(VOID)(param);

	/* convert the timestamp to readable format  преобразует временную метку в привычный формат %H:%M:%S*/
	local_tv_sec = header->ts.tv_sec;			//берем метку из универсального заголовка
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);	//перед время в функцию

	/* print timestamp and length of the packet  Вывести метку времени и длину пакета*/


	mh = (mac_header *)(pkt_data);
	/* retireve the position of the ip header */		//Смещаем указатель заголовка на 14 символов(длина заголовка MAC) IP-Заголовок расположен сразу после заголовка MAC.
	ih = (ip_header *)(pkt_data +						//Мы извлекем IP-адрес источника и адрес назначения из IP-заголовка.
		14); //length of ethernet header
	ah = (arp_header *)(pkt_data +
		14);

	/* retireve the position of the udp header */		//берем UDP Header
	ip_len = (ih->ver_ihl & 0xf) * 4;					//Достижение заголовка UDP немного сложнее, потому что Заголовок IP не имеет фиксированной длины.
	uh = (udp_header *)((u_char*)ih + ip_len);			//Поэтому мы используем поле длины заголовка IP, чтобы узнать его размер.
	th = (tcp_header *)((u_char*)ih + ip_len);

	//Как только мы узнаем расположение заголовка UDP, мы извлекаем порты источника и назначения.

	/* convert from network byte order to host byte order Преобразование big-endian в сетевой*/
	udp_len = ntohs(uh->len);
	udp_sport = ntohs(uh->sport); //конвертирует 16-битную беззнаковую величину из локального порядка байтов в сетевой
	udp_dport = ntohs(uh->dport);
	tcp_sport = ntohs(th->sport);
	tcp_dport = ntohs(th->dport);

	/* print ip addresses and udp ports выводится 4 байта IP адрес источника, затем UDP источника(Кому?). 4 байта и UDP отправителя(От кого?)*/

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
	case(0X800) :
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

		if (ih->proto == 1)
		{ //Запрет передачи ICMP-запросов c узла B на узел D.
			printf("\nProtocol type: ICMP\n");
			if (ih->saddr == b_ip && ih->daddr == d_ip && disallow_b_d) {
				printf("\nFiltering\n");
				flag_send = false;
				//mh->dmac = mh->smac;
			}

		}
		else if (ih->proto == 6)
		{
			printf("\nProtocol type: TCP\n");
			printf("SP:%d -> DP:%d\n",
				udp_sport,
				udp_dport);
			if (disallow_except_b_c) { //Разрешение передачи сообщений по протоколу TCP только между узлами B и C.
				flag_send = false;
				if ( (ih->saddr == b_ip && ih->daddr == c_ip) ||
					 (ih->saddr == c_ip && ih->daddr == b_ip) ) {
					flag_send = true;
				}
			}
			printf("Length: %d\n\n\n\n", th->offset);
			printf("Checksum: %X\n\n\n\n", ntohs(th->checksum));
		}
		else if (ih->proto == 17)
		{
			printf("\nProtocol type: UDP\n");
			printf("SP:%d -> DP:%d\n",
				tcp_sport,
				tcp_dport);
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

	int if_num = atoi((const char *)param);
	if (sw_table.find(mh->smac) == sw_table.end()) {
		sw_queue.push(mh->smac);			//таким образом имеем очередь с мак адресами без повторов. которые надо удалять в порядке следования очереди
	}
	sw_table.insert(std::pair<mac_address, int>((mac_address)mh->smac, if_num));
	it = sw_table.find(mh->dmac);
	it_s = sw_table.find(mh->smac);
	
	if (flag_send) {

		if (it_s != sw_table.end() && it != sw_table.end()) {
			if (it_s->second == if_num && it->second != if_num) {
				switch (it_s->second) {
				case 1: {
							if (pcap_sendpacket(iface2, pkt_data, header->len) != 0) {
								fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr((pcap_t *)param));
								return;
							}
							break;
				}
				case 2: {
							if (pcap_sendpacket(iface1, pkt_data, header->len) != 0) {
								fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr((pcap_t *)param));
								return;
							}
							break;
				}
				}
			}
		}
		else if (it != sw_table.end()) {
			if (it->second != if_num) {
				switch (it_s->second) {
				case 1: {
							if (pcap_sendpacket(iface2, pkt_data, header->len) != 0) {
								fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr((pcap_t *)param));
								return;
							}
							break;
				}
				case 2: {
							if (pcap_sendpacket(iface1, pkt_data, header->len) != 0) {
								fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr((pcap_t *)param));
								return;
							}
							break;
				}
				}
			}
		}
		else if (it_s != sw_table.end()) {
			if (it_s->second == if_num) {
				switch (it_s->second) {
				case 1: {
							if (pcap_sendpacket(iface2, pkt_data, header->len) != 0) {
								fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr((pcap_t *)param));
								return;
							}
							break;
				}
				case 2: {
							if (pcap_sendpacket(iface1, pkt_data, header->len) != 0) {
								fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr((pcap_t *)param));
								return;
							}
							break;
				}
				}
			}
		}
		else
		{
			switch (if_num) {
			case 1: {
						if (pcap_sendpacket(iface2, pkt_data, header->len) != 0) {
							fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr((pcap_t *)param));
							return;
						}
						break;
			}
			case 2: {
						if (pcap_sendpacket(iface1, pkt_data, header->len) != 0) {
							fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr((pcap_t *)param));
							return;
						}
						break;
			}
			}
		}
	}

	//---------------------- WORK WITH FILE
	if (flag_send == true && start_pcap_allow)
	{
		pcap_dump((u_char *)dfile_allow, header, pkt_data);
	}
	else if (flag_send == false && start_pcap_disallow)
	{
		pcap_dump((u_char *)dfile_disallow, header, pkt_data);
	}
	//---------------------- WORK WITH FILE END
	
	flag_send = true;
	lock_mutex.unlock();
}
	
bool mac_address:: operator==(const mac_address &o)const {
	return byte1 == o.byte1 && byte2 == o.byte2 && byte3 == o.byte3 && byte4 == o.byte4 && byte5 == o.byte5 && byte6 == o.byte6;
}
	
bool mac_address:: operator<(const mac_address &o)const {
	return byte1 < o.byte1 || byte1 == o.byte1 && byte2 < o.byte2 || byte1 == o.byte1 && byte2 == o.byte2 && byte3 < o.byte3
		|| byte1 == o.byte1 && byte2 == o.byte2 && byte3 == o.byte3 && byte4 < o.byte4
		|| byte1 == o.byte1 && byte2 == o.byte2 && byte3 == o.byte3 && byte4 == o.byte4 && byte5 < o.byte5
		|| byte1 == o.byte1 && byte2 == o.byte2 && byte3 == o.byte3 && byte4 == o.byte4 && byte5 == o.byte5 && byte6 < o.byte6;
}

bool ip_address:: operator==(const ip_address &o)const {
	return byte1 == o.byte1 && byte2 == o.byte2 && byte3 == o.byte3 && byte4 == o.byte4;
}


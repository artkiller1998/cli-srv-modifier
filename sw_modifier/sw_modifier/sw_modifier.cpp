#include <thread>
#include "pcap.h"
#include "stdint.h"
#include <atomic>
#include <map>
#include <mutex>
#include <ctime>
#include <queue>
//#include <winsock2.h>
//#include <ws2tcpip.h>
#include <set>
#include "fstream"

#define TIMEOUT_SW_TABLE 4

//**********************************************************
// STRUCTURES
//**********************************************************

/* 4 bytes IP address  Структура обохначает 4-ех байтовый формат адреса*/	
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;

	bool  operator==(const ip_address &o)const;
}ip_address;

typedef struct tcp_pseudoheader{
	struct ip_address srcAddr;
	struct ip_address destAddr;
	uint8_t zeroes;
	uint8_t protocol;
	uint16_t len;
}tcp_pseudoheader;

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

typedef struct {
	uint8_t kind;
	uint8_t size;
} tcp_option_t;

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


//*****************************************************************
// FUNCTION: in_cksum
// Calculates the TCP Checksum 
// This produces the same checksum as csum, but the checksum is
// still reported as incorrect by Ethereal, and it also differs from
// the CRC of the corresponding packet of the input ethereal/tcpdump file
//*****************************************************************
u_short in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
	{
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum; return(answer);
}

u_short crc(u_short *addr, int count)
{
	/* Расчет контрольной суммы Internet для count байтов,
	* начиная с addr.
	*/
	register long sum = 0;
	u_short checksum = 0;

	while (count > 1)  {
		/*  Внутренний цикл */
		sum += * addr++;
		count -= 2;
	}

	/*  Прибавляем байт переноса, если он есть */
	if (count > 0)
		sum += *(unsigned char *)addr;

	/*  поместим 32-битовую сумму в 16 битов */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	checksum = ~sum;
	return checksum;
}

std::atomic_bool flag_exit = ATOMIC_VAR_INIT(false);
bool flag_send = true;
bool disallow_b_d = false;
bool disallow_except_b_c = false;
bool start_pcap_disallow = false;
bool start_pcap_allow = false;
bool modify_a_c = false;

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

ip_address zero_ip;
ip_address a_ip;
ip_address b_ip;
ip_address c_ip;
ip_address d_ip;
u_short a_port;
u_short b_port;
u_short c_port;
u_short d_port;
mac_address mac_a;

struct sockaddr_in a_addr;
struct in_addr b_addr;
struct in_addr c_addr;
struct in_addr d_addr;

char _a_ip[20] = "";
char _b_ip[20] = "";
char _c_ip[20] = "";
char _d_ip[20] = "";
char _a_port[10] = "";
char _b_port[10] = "";
char _c_port[10] = "";
char _d_port[10] = "";

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
	pcap_loop () похож на pcap_dispatch (), за исключением того,
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
	zero_ip.byte1 = 0;
	zero_ip.byte2 = 0;
	zero_ip.byte3 = 0;
	zero_ip.byte4 = 0;

	std::fstream file("sw_modifier.cfg");
	if (file.is_open() && file.peek() != EOF) {
		printf("sw_modifier.cfg --- is opened\n\n"); // если открылс¤
		file >> _a_ip;
		file >> _a_port;
		file >> _b_ip;
		file >> _b_port; 
		file >> _c_ip;
		file >> _c_port;
		file >> _d_ip;
		file >> _d_port;
	}
	else {
		printf("sw_modifier.cfg --- is empty or can`t be opened!\n"); // если первый символ конец файла
	}
	file.close();

	sscanf_s(_a_ip, "%d.%d.%d.%d", &a_ip.byte1, &a_ip.byte2, &a_ip.byte3, &a_ip.byte4);
	sscanf_s(_b_ip, "%d.%d.%d.%d", &b_ip.byte1, &b_ip.byte2, &b_ip.byte3, &b_ip.byte4);
	sscanf_s(_c_ip, "%d.%d.%d.%d", &c_ip.byte1, &c_ip.byte2, &c_ip.byte3, &c_ip.byte4);
	sscanf_s(_d_ip, "%d.%d.%d.%d", &d_ip.byte1, &d_ip.byte2, &d_ip.byte3, &d_ip.byte4);
	a_port = htons(atoi(_a_port));
	b_port = htons(atoi(_b_port));
	c_port = htons(atoi(_c_port));
	d_port = htons(atoi(_d_port));

	printf("\nA IP %d.%d.%d.%d\n", a_ip.byte1, a_ip.byte2, a_ip.byte3, a_ip.byte4);
	printf("B IP %d.%d.%d.%d\n", b_ip.byte1, b_ip.byte2, b_ip.byte3, b_ip.byte4);
	printf("C IP %d.%d.%d.%d\n", c_ip.byte1, c_ip.byte2, c_ip.byte3, c_ip.byte4);
	printf("D IP %d.%d.%d.%d\n", d_ip.byte1, d_ip.byte2, d_ip.byte3, d_ip.byte4);

	printf("A PORT %d\n", ntohs(a_port));
	printf("B PORT %d\n", ntohs(b_port));
	printf("C PORT %d\n", ntohs(c_port));
	printf("D PORT %d\n", ntohs(d_port));

	system("PAUSE");

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

	////set MAC addresses
	//A MAC 00:0C:29:25:8B:CA
	
	mac_a.byte1 = 0x00;
	mac_a.byte2 = 0x0C;
	mac_a.byte3 = 0x29;
	mac_a.byte4 = 0x25;
	mac_a.byte5 = 0x8B;
	mac_a.byte6 = 0xCA;

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
		{
			modify_a_c = modify_a_c ? false : true;
			printf("\nModifying trafficfrom from 'A -> C' to 'B -> C' now is: %s\n", modify_a_c ? "Enable" : "Disable");
			system("PAUSE");
			break;
		}
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
			printf("Wrong choise\n");
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
	lock_mutex.lock();
	if (flag_exit)
	{
		return;
	}
	//Это решает проблему различных заголовков для различных интерфейсов пакета.
	struct tm ltime;	
	char timestr[16];	//массив на 16 символов
	ip_header *ih;		//элемент структуры Заголовок IP
	mac_header *mh;
	udp_header *uh;		////элемент структуры Заголовок UDP
	arp_header *ah;
	tcp_header *th;		////элемент структуры Заголовок TCP
	char *data = "";
	int datalen = 0;
	u_int ip_len;		//unsigned Длина ip
	u_int udp_len;
	u_short udp_sport, udp_dport; //unsigned UDP source port,destination port
	u_short tcp_sport, tcp_dport;
	time_t local_tv_sec; //метка времени
	mh = (mac_header *)(pkt_data);
	ih = (ip_header *)(pkt_data +						//Мы извлекем IP-адрес источника и адрес назначения из IP-заголовка.
		14); //length of ethernet header
	ip_len = (ih->ver_ihl & 0xf) * 4;					//Достижение заголовка UDP немного сложнее, потому что Заголовок IP не имеет фиксированной длины.
	uh = (udp_header *)((u_char*)ih + ip_len);			//Поэтому мы используем поле длины заголовка IP, чтобы узнать его размер.
	th = (tcp_header *)((u_char*)ih + ip_len);
	tcp_sport = ntohs(th->sport);
	tcp_dport = ntohs(th->dport);

	switch (ntohs(mh->etype))
	{
	case(0X800) :
	{
		if (ih->proto == 1) { //Запрет передачи ICMP-запросов c узла B на узел D.
			if (ih->saddr == b_ip && ih->daddr == d_ip && disallow_b_d) {
				flag_send = false;
			}
		}
		else if (ih->proto == 6)
		{
			if (modify_a_c && (ih->saddr == a_ip && ih->daddr == c_ip || (ih->saddr == c_ip && ih->daddr == b_ip))) //Подмена по IP-адресу ///!!!!b_ip
			{	//и номеру порта TCP-сервера узла A на узел B 
				//ПЕРЕСЧЕТ IP

				if (ih->saddr == a_ip && ih->daddr == c_ip) {
					ih->saddr = b_ip;
					th->sport = b_port;
				}

				if (ih->saddr == c_ip && ih->daddr == b_ip) {  
					ih->daddr = a_ip;
					mh->dmac = mac_a;
					th->dport = a_port;
				}
			
				ih->crc = 0;
				char ipBuf[4096];
				memcpy(ipBuf, ih, 20);
				char saddr[30] = "";
				char daddr[30] = "";
				sprintf(saddr, "%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
				sprintf(daddr, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
				ih->crc = crc((u_short *)ipBuf, 20);
				//ПЕРЕСЧЕТ TCP
				th->checksum = 0;
				tcp_pseudoheader psd_header; //создаем псевдозаголовок и заполняем его
				psd_header.destAddr = ih->daddr;
				psd_header.srcAddr = ih->saddr;
				psd_header.zeroes = 0;
				psd_header.protocol = IPPROTO_TCP;
				data = (char *)((u_char*)ih + ip_len + 20); //считываем данные
				datalen = htons(ih->len) - 40;
				psd_header.len = htons(sizeof(tcp_header)+datalen); //задаем длину псевдохедера

				char tcpBuf[65536];	//буфер передаваемый в cksum
				memcpy(tcpBuf, &psd_header, sizeof(tcp_pseudoheader));
				memcpy(tcpBuf + sizeof(tcp_pseudoheader),th, sizeof(tcp_header));
				memcpy(tcpBuf + sizeof(tcp_pseudoheader)+sizeof(tcp_header), data, datalen);
				th->checksum = in_cksum((u_short *)tcpBuf, sizeof(tcp_pseudoheader)+sizeof(tcp_header)+datalen);
			}
			if (disallow_except_b_c) { //Разрешение передачи сообщений по протоколу TCP только между узлами B и C.
				flag_send = false;
				if ( (ih->saddr == b_ip && ih->daddr == c_ip) ||
					 (ih->saddr == c_ip && ih->daddr == b_ip) ) {
					flag_send = true;
				}
			}
		}
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


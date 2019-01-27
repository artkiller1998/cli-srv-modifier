#include "pcap.h"
#include "stdint.h"

/* 4 bytes IP address  Структура обохначает 4-ех байтовый формат адреса*/		//зачем TYPEDEF?
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

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main()
{
	pcap_if_t *alldevs; //элемент в списке интерфейсов
	pcap_if_t *d;
	int inum;
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

	printf("Enter the interface number (1-%d):", i);			//просит выбрать интерфейс
	scanf_s("%d", &inum);										// интерфейс нум с клавиатуры

	if (inum < 1 || inum > i)									//ввел несуществующий интерфейс
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);								//освобождает устройства списка выделенного pcap_findalldevs
		return -1;
	}

	/* Jump to the selected adapter переместить указатель на выбранный адаптер*/
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

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
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. ПроверЯет канал передачи данных адаптера.Если не интернет - ошибка */
	if (pcap_datalink(adhandle) != DLT_EN10MB) 
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
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
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter устанавливаем
	if (pcap_setfilter(adhandle, &fcode)<0)				//если не уст ош освоб
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);			//при наличии интерфейса выведет описание. 

	/* At this point, we don't need any more the device list. Free it Список устр не нужен. Освободим его*/
	pcap_freealldevs(alldevs);

	/* start the capture начинаем слушать 
	луп pcap_loop () похож на pcap_dispatch (), за исключением того, 
	что он продолжает считывать пакеты до тех пор, пока не будут обработаны пакеты cnt или возникнет ошибка*/
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet    Функция обратного вызова вызывается в libpcap для каждого входящего пакета*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) //unsigned, Каждый пакет в файле дампа добавляется к этому универсальному заголовку. 																					
{		
	//Это решает проблему различных заголовков для различных интерфейсов пакета.
	struct tm ltime;	//?
	char timestr[16];	//массив на 16 символов
	ip_header *ih;		//элемент структуры Заголовок IP
	mac_header *mh;
	udp_header *uh;		////элемент структуры Заголовок UDP
	arp_header *ah;
	u_int ip_len;		//unsigned Длина ip
	u_int udp_len;
	u_short sport, dport; //unsigned UDP source port,destination port
	time_t local_tv_sec; //метка времени

	/*
	* Unused variable		???
	*/
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
														//Как только мы узнаем расположение заголовка UDP, мы извлекаем порты источника и назначения.

	/* convert from network byte order to host byte order Преобразование big-endian в сетевой*/
	udp_len = ntohs(uh->len);
	sport = ntohs(uh->sport); //конвертирует 16-битную беззнаковую величину из локального порядка байтов в сетевой
	dport = ntohs(uh->dport);

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
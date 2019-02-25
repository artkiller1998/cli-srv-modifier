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
std::map<mac_address, int>::iterator it;
int timeout = 20;

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
		thr_err = ATOMIC_VAR_INIT(true);
	}

	/* Check the link layer. We support only Ethernet for simplicity. ПроверЯет канал передачи данных адаптера.Если не интернет - ошибка */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
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
		thr_err = ATOMIC_VAR_INIT(true);
	}

	//set the filter устанавливаем
	if (pcap_setfilter(adhandle, &fcode)<0)				//если не уст ош освоб
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
	}

	printf("\nlistening on %s...\n", d->description);			//при наличии интерфейса выведет описание. 

	/* At this point, we don't need any more the device list. Free it Список устр не нужен. Освободим его*/
	//pcap_freealldevs(alldevs);
	



	/* start the capture начинаем слушать
	луп pcap_loop () похож на pcap_dispatch (), за исключением того,
	что он продолжает считывать пакеты до тех пор, пока не будут обработаны пакеты cnt или возникнет ошибка*/
	pcap_loop(adhandle, 0, packet_handler, (u_char *)"1");
}

void iface2_thr(pcap_if_t *d, pcap_t *adhandle, u_int netmask, struct bpf_program fcode, char *packet_filter)
//{}
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
		thr_err = ATOMIC_VAR_INIT(true);
	}

	/* Check the link layer. We support only Ethernet for simplicity. ПроверЯет канал передачи данных адаптера.Если не интернет - ошибка */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
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
		thr_err = ATOMIC_VAR_INIT(true);
	}

	//set the filter устанавливаем
	if (pcap_setfilter(adhandle, &fcode)<0)				//если не уст ош освоб
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		thr_err = ATOMIC_VAR_INIT(true);
	}

	printf("\nlistening on %s...\n", d->description);			//при наличии интерфейса выведет описание. 

	/* At this point, we don't need any more the device list. Free it Список устр не нужен. Освободим его*/
	//pcap_freealldevs(alldevs);

	/* start the capture начинаем слушать
	луп pcap_loop () похож на pcap_dispatch (), за исключением того,
	что он продолжает считывать пакеты до тех пор, пока не будут обработаны пакеты cnt или возникнет ошибка*/
	pcap_loop(adhandle, 0, packet_handler, (u_char *)"2");
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

	/* Jump to the selected adapter переместить указатель на выбранный адаптер*/
	d = alldevs;
	std::thread thr_1(iface1_thr, d, adhandle, netmask, fcode, packet_filter);
	d = d->next;
	std::thread thr_2(iface2_thr, d, adhandle, netmask, fcode, packet_filter);
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
			timeout = (int)getchar();
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
	pcap_freealldevs(alldevs);
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet    Функция обратного вызова вызывается в libpcap для каждого входящего пакета*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) //unsigned, Каждый пакет в файле дампа добавляется к этому универсальному заголовку. 																					
{
	//if ( ((time(NULL) % timeout) == 0)
		
	mac_header *mh;
	mh = (mac_header *)(pkt_data);
	lock_mutex.lock();
	sw_table.insert(std::pair<mac_address, int>((mac_address)mh->smac, atoi((const char *)param)));
	lock_mutex.unlock();
	//print_sw_table();
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
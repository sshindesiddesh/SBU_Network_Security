#include <iostream>
#include <pcap.h>
#include <string.h>
#include <common.h>
#include <arpa/inet.h>
#include <string>

/*TODO:fff mac problem */

using namespace std;

uint8_t arg_flag = 0;

#define set_flag(y) (arg_flag |= (1 << y))
#define get_flag(y) (arg_flag & (1 << y))
#define clr_flag(y) (arg_flag & ~(1 << y))

#define	ARG_FLAG_STRING		0
#define	ARG_FLAG_DEVICE		1
#define	ARG_FLAG_FILE		2
#define ARG_FLAG_EXP		3

#define ETHERTYPE_IP		0x800
#define ETHERTYPE_ARP		0x806
#define ETHERTYPE_RARP		0x8035

struct in_args_t {
	char *dev;
	char *file;
	char *string;
	char *exp;
};

in_args_t in_args;

int parse_args(int argc, char *argv[])
{
	/* No argument is given */
	if (argc == 1)
		arg_flag = 0;

	int i = 0;
	char x = 0;
	for (i = 1; i < argc;) {
		if (argv[i][0] == '-' && (strlen(argv[i]) == 2))
			x = argv[i][1];
		else {
				in_args.exp = strdup(argv[i]);
				set_flag(ARG_FLAG_EXP);
				i++;
				continue;
		}
		switch (x) {
			case 'r':
				in_args.file = strdup(argv[i + 1]);
				set_flag(ARG_FLAG_FILE);
				i += 2;
				break;
			case 's':
				in_args.string = strdup(argv[i + 1]);
				set_flag(ARG_FLAG_STRING);
				i += 2;
				break;
			case 'i':
				in_args.dev = strdup(argv[i + 1]);
				set_flag(ARG_FLAG_DEVICE);
				i += 2;
				break;
			default:
				i++;
				break;
		}
	}
}

#define ETH_LEN		6
#define IP_LEN		4
#define ADDRESS_LEN	20

/* See if fragmented printing is reauired here. This is would be better for str matching */
#define PAYLOAD_MAX_LEN	(4096 * 8)
struct out_t {
	/*  IP */
	struct timeval ts;
	uint8_t src_mac[ETH_LEN];
	uint8_t dst_mac[ETH_LEN];
	uint16_t eth_type;
	char src_ip[ADDRESS_LEN];
	uint16_t src_port;
	char dst_ip[ADDRESS_LEN];
	uint16_t dst_port;
	char protocol[10];
	uint64_t len;
	string payload;
	uint64_t payload_len;
	/* ARP */
	uint8_t sender_mac[ETH_LEN];
	uint8_t target_mac[ETH_LEN];
	uint8_t sender_ip[IP_LEN];
	uint8_t target_ip[IP_LEN];
	int arp_len;
};

/* Output structure to print the fields  */
out_t out;

/* Print the payload in hex and human readable format */
void print_payload(uint8_t *buf)
{
	int i = 0, j = 0;

	while (1) {
		for (i = 0; i < 16 && ((i + j) < out.payload_len); i++) {
			printf("%.2x ", buf[j + i]);
			if (i != 0 && i % 16 == 0)
				printf("\n");
		}

		/* Adjust the char print for last line */
		if ((i + j) == out.payload_len)
			for (int k = 0; k < (16 - (out.payload_len % 16)); k++)
				/* 3 spaces per char */
				printf("   ");

		/* 4 spaces */
		printf("    ");
		for (i = 0; i < 16 && ((i+ j)  < out.payload_len); i++) {
			printf("%c", out.payload[j + i]);
			if (i != 0 && i % 16 == 0)
				printf("\n");
		}

		if ((i + j) == out.payload_len)
			break;
		j += 16;
		printf("\n");
	}
	printf("\n");
}

void print_out(u_char *payload)
{
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];

	nowtime = out.ts.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
	snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, out.ts.tv_usec);

	cout << buf << " ";
	for (int i = 0; i < 6; i++) {
		printf("%.2x", out.src_mac[i]);
		if (i != 5)
			cout << ":";
	}
	cout << " -> " ;
	for (int i = 0; i < 6; i++) {
		printf("%.2x", out.dst_mac[i]);
		if (i != 5)
			cout << ":";
	}
	printf(" type 0x%x", out.eth_type);
	cout << " len " << out.len;
	cout << " " << out.src_ip << ":" << out.src_port << " -> " << out.dst_ip << ":" << out.dst_port << " ";
	cout << " " << out.protocol;

	cout << endl;

	print_payload(payload);
}

void print_arp()
{
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];

	nowtime = out.ts.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
	snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, out.ts.tv_usec);

	cout << buf << " ";
	for (int i = 0; i < 6; i++) {
		printf("%.2x", out.src_mac[i]);
		if (i != 5)
			cout << ":";
	}
	cout << " -> " ;
	for (int i = 0; i < 6; i++) {
		printf("%.2x", out.dst_mac[i]);
		if (i != 5)
			cout << ":";
	}
	printf(" type 0x%x", out.eth_type);
	cout << " len " << out.arp_len << " ";

	for (int i = 0; i < 4; i++) {
		printf("%d", out.sender_ip[i]);
		if (i != 3)
			cout << ".";
	}
	cout << " -> " ;
	for (int i = 0; i < 4; i++) {
		printf("%d", out.target_ip[i]);
		if (i != 3)
			cout << ".";
	}

	cout << " " << out.protocol;

	cout << endl;
}

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct sniff_ethernet *eth;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	u_char *payload;
	int ip_size, tcp_size;
	out.ts = header->ts;

	out.len = header->len;
	eth = (struct sniff_ethernet *)packet;
	memcpy(out.src_mac, eth->ether_shost, 6);
	memcpy(out.dst_mac, eth->ether_dhost, 6);
	out.eth_type = ntohs(eth->ether_type);

	switch (out.eth_type) {
		case ETHERTYPE_IP:
			break;
		case ETHERTYPE_ARP:
		{
			arp_hdr_t *arp_hdr = (arp_hdr_t *)(packet + SIZE_ETH_HDR);
			memcpy(out.sender_ip, arp_hdr->sender_ip, 4);
			memcpy(out.target_ip, arp_hdr->target_ip, 4);
			out.arp_len = out.len - SIZE_ETH_HDR;
			strcpy(out.protocol, "ARP");
			print_arp();
			return;
			break;
		}
		default:
			cout << "RAW PACKET" << endl;
			print_payload((uint8_t *)(packet + SIZE_ETH_HDR));
			return;
	}

	ip = (struct sniff_ip *)(packet + SIZE_ETH_HDR);
	ip_size = IP_HL(ip) * 4;
	if (ip_size < 20) {
		return;
		ip_size = 0;
	}
#if 0
		cout << "Not a IP packet" << endl;
#endif

	strcpy(out.src_ip, inet_ntoa(ip->ip_src));
	strcpy(out.dst_ip, inet_ntoa(ip->ip_dst));

	/* Refered from netiner/in.h */
	switch (ip->ip_p) {
		case IPPROTO_TCP:
			strcpy(out.protocol, "TCP");
			break;
		case IPPROTO_UDP:
			strcpy(out.protocol, "UDP");
			break;
		case IPPROTO_ICMP:
			strcpy(out.protocol, "ICMP");
			break;
		case IPPROTO_IGMP:
			strcpy(out.protocol, "IGMP");
			return;
		case IPPROTO_IP:
			strcpy(out.protocol, "IP");
			return;
		default:
			cout << "OTHER" << endl;
			strcpy(out.protocol, "OTHER");
			return;
	}

	tcp = (struct sniff_tcp *)(packet + SIZE_ETH_HDR + ip_size);
	tcp_size = TH_OFF(tcp) * 4;
	if (tcp_size < 20)
		tcp_size = 0;
#if 0
		cout << "Not a TCP packet" << endl;
#endif

	out.src_port = ntohs(tcp->th_sport);
	out.dst_port = ntohs(tcp->th_dport);

	payload = (u_char *)(packet + SIZE_ETH_HDR + ip_size + tcp_size);
	out.payload_len = out.len - (SIZE_ETH_HDR + ip_size + tcp_size);

	out.payload = "";
	int i;
	/* TODO: Try checking for 10, 11 and 13 also */
	for (i = 0; i < out.payload_len; i++) {
		if (isprint(payload[i]))
			out.payload += (char)payload[i];
		else
			out.payload += '.';
	}

	if (get_flag(ARG_FLAG_STRING)) {
		if (out.payload.find(string(in_args.string)) != std::string::npos) {
			print_out(payload);
			return;
		} else
			return;
	}

	print_out(payload);

	/* Reset the values */
	out.len = 0;
	out.payload = "";
	out.payload_len = 0;
}

int main(int argc, char *argv[])
{
	/* Parse and populate all the input arguments */
	parse_args(argc, argv);

/* TODO: Delete */
/* Check for args. Remove later */
#if 0
	if (get_flag(ARG_FLAG_STRING))
		cout << "STRING " << in_args.string << endl;
	if (get_flag(ARG_FLAG_DEVICE))
		cout << "DEVICE " << in_args.dev << endl;
	if (get_flag(ARG_FLAG_EXP))
		cout << "EXP " << in_args.exp << endl;
	if (get_flag(ARG_FLAG_FILE))
		cout << "FILE " << in_args.file << endl;
	return 0;
#endif

	char *dev, err_buf[PCAP_ERRBUF_SIZE];

	pcap_t *handle;
	struct bpf_program fp;
	char *filter_exp = in_args.exp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

	/* If device is given by the user. */
	if (get_flag(ARG_FLAG_DEVICE)) {
		dev = in_args.dev;
	/* If file given by the device */
	} else if (get_flag(ARG_FLAG_FILE)) {
		handle = pcap_open_offline(in_args.file, err_buf);
		goto PROCESS;
	/* Lookup for devices */
	} else {
		dev = pcap_lookupdev(err_buf);
		if (dev == NULL)
			cout << "No Device Found" << endl;
	}

	if (pcap_lookupnet(dev, &net, &mask, err_buf) == -1) {
		cout << "Caould not get netmask : Error " << err_buf << endl;
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, err_buf);
	if (handle == NULL)
		cout << "Could not open device "  << dev << " : Error : " << err_buf << endl;

PROCESS:
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
		cout << "Could not parse filter" << endl;

	if (pcap_setfilter(handle, &fp) == -1)
		cout << "Could not install filter " << endl;

	pcap_loop(handle, -1, callback, NULL);

	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}

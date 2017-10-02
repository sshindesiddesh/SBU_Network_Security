#include <iostream>
#include <pcap.h>
#include <string.h>
#include <common.h>
#include <arpa/inet.h>

/*TODO: ARP, RARP, str matching */

using namespace std;

uint8_t arg_flag = 0;

#define set_flag(y) (arg_flag |= (1 << y))
#define get_flag(y) (arg_flag & (1 << y))
#define clr_flag(y) (arg_flag & ~(1 << y))

#define	ARG_FLAG_STRING		0
#define	ARG_FLAG_DEVICE		1
#define	ARG_FLAG_FILE		2
#define ARG_FLAG_EXP		3

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
#define ADDRESS_LEN	20

/* See if fragmented printing is reauired here. This is would be better for str matching */
#define PAYLOAD_MAX_LEN	(4096 * 8)
struct out_t {
	uint8_t src_mac[ETH_LEN];
	uint8_t dst_mac[ETH_LEN];
	uint16_t eth_type;
	char src_ip[ADDRESS_LEN];
	uint16_t src_port;
	char dst_ip[ADDRESS_LEN];
	uint16_t dst_port;
	char protocol[10];
	uint64_t len;
	uint8_t payload[PAYLOAD_MAX_LEN];
	uint64_t payload_len;
};

out_t out;

int count = 0;

void print_out()
{
	cout << count++ << " ";
	for (int i = 0; i < 6; i++) {
		printf("%.2x", out.dst_mac[i]);
		if (i != 5)
			cout << ":";
	}
	cout << " -> " ;
	for (int i = 0; i < 6; i++) {
		printf("%.2x", out.src_mac[i]);
		if (i != 5)
			cout << ":";
	}
	printf(" 0x%x ", out.eth_type);
	cout << " " << out.src_ip << ":" << out.src_port << " -> " << out.dst_ip << ":" << out.dst_port << " ";
	cout << " " << out.protocol;
	cout << " " << out.len;

	cout << endl;

	int i;
	/* TODO: Try checking for 10, 11 and 13 also */
	for (i = 0; i < out.payload_len; i++) {
		if ((out.payload[i] >= 32 && out.payload[i] <= 126))
			out.payload[i] = (char)out.payload[i];
		else
			out.payload[i] = '.';
	}
	out.payload[i] = (char)'\0';

	cout << " " << (char *)out.payload << endl;

	cout << endl;
}

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct sniff_ethernet *eth;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	u_char *payload;
	int ip_size, tcp_size;

	out.len = header->len;
	eth = (struct sniff_ethernet *)packet;
	memcpy(out.src_mac, eth->ether_shost, 6);
	memcpy(out.dst_mac, eth->ether_dhost, 6);
	out.eth_type = ntohs(eth->ether_type);

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
			strcpy(out.protocol, "OTHER");
			return;
	}

	tcp = (struct sniff_tcp *)(packet + SIZE_ETH_HDR + ip_size);
	tcp_size = TH_OFF(tcp)*4;
	if (tcp_size < 20)
		tcp_size = 0;
#if 0
		cout << "Not a TCP packet" << endl;
#endif

	out.src_port = ntohs(tcp->th_sport);
	out.dst_port = ntohs(tcp->th_dport);

	payload = (u_char *)(packet + SIZE_ETH_HDR + ip_size + tcp_size);
	out.payload_len = out.len - (SIZE_ETH_HDR + ip_size + tcp_size);

	memcpy(out.payload, payload, out.payload_len);
	print_out();
}

int main(int argc, char *argv[])
{
	/* Parse and populate all the input arguments */
	parse_args(argc, argv);

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

	if (get_flag(ARG_FLAG_DEVICE)) {
		dev = in_args.dev;
	} else if (get_flag(ARG_FLAG_FILE)) {
		handle = pcap_open_offline(in_args.file, err_buf);
		goto PROCESS;
	} else {
		dev = pcap_lookupdev(err_buf);
		if (dev == NULL)
			cout << "No Device Found" << endl;
		cout << "Device " << dev << endl;
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

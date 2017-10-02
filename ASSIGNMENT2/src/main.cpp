#include <iostream>
#include <pcap.h>
#include <string.h>
#include <common.h>

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

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	cout << "C:Len " << header->len << endl;
	const struct sniff_ethernet *eth;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	int ip_size, tcp_size;
	u_char *payload;

	eth = (struct sniff_ethernet *)packet;
	ip = (struct sniff_ip *)(packet + SIZE_ETH_HDR);
	ip_size = IP_HL(ip) * 4;
	if (ip_size < 20)
		cout << "Not a IP packet" << endl;
	/* Refered from netiner/in.h */
	switch (ip->ip_p) {
		case IPPROTO_TCP:
			printf("TCP\n");
			break;
		case IPPROTO_UDP:
			printf("UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("ICMP\n");
			return;
		case IPPROTO_IGMP:
			printf("IGMP\n");
			return;
		case IPPROTO_IP:
			printf("IP\n");
			return;
		default:
			printf("OTHER\n");
			return;
	}
	tcp = (struct sniff_tcp *)(packet + SIZE_ETH_HDR + ip_size);
	tcp_size = TH_OFF(tcp)*4;
	if (tcp_size < 20)
		cout << "Not a TCP packet" << endl;
	payload = (u_char *)(packet + SIZE_ETH_HDR + ip_size + tcp_size);


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

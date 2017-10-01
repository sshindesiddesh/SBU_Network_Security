#include <iostream>
#include <pcap.h>

using namespace std;

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	cout << "C:Len " << header->len << endl;
}

int main(int argc, char *argv[])
{
	cout << "Hello World" << endl;
	char *dev, err_buf[PCAP_ERRBUF_SIZE];

	pcap_t *handle;
	struct bpf_program fp;
	char filter_exp[] = "";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

	dev = pcap_lookupdev(err_buf);
	if (dev == NULL)
		cout << "No Device Found" << endl;
	cout << "Device " << dev << endl;

	if (pcap_lookupnet(dev, &net, &mask, err_buf) == -1) {
		cout << "Caould not get netmask : Error " << err_buf << endl;
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, err_buf);
	if (handle == NULL)
		cout << "Could not open device "  << dev << " : Error : " << err_buf << endl;

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
		cout << "Could not parse filter" << endl;

	if (pcap_setfilter(handle, &fp) == -1)
		cout << "Could not install filter " << endl;

	packet = pcap_next(handle, &header);
	cout << "Grabbed a packet with lenght : " << header.len << endl;

	pcap_loop(handle, -1, callback, NULL);

	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}

#include <stdio.h>
#include <pcap.h>
/** Ethernet adreses are 6 bytes */
void collback (u_char args, const struct pcap_pkthdr *header, const u_char *packet)
{
    
    return;

}
int main (int args, char **argv)
{
    char *device;
    char error [PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snaplen = BUFSIZ; /**The maximum number of bytes to be captured by pcap */
    int promiscuous = 0; /* to set up promiscuous mode for interface*/
    int to_ms = 1000;/*the read time out*/
    struct bpf_program fp; /* the compiled filtered expression */
    char filter_exp [] = "port 443"; /** The filter expression*/
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */
    struct pcap_pkthdr header; /* The header that pcap gives us*/
    int optimize = 0; /* Optimize ?*/
    const u_char *packet;    /** The actual packet*/

    /*find a device*/
    device = pcap_lookupdev (error);
    if(device == NULL) 
    {
        printf("Any default device found: %s\n", error);
        return 0;
    }
    /** find the property for the device*/
    if(pcap_lookupnet(device, &net, &mask, error) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", device);

    }

    /**Opening the device for sniffing*/   
    handle = pcap_open_live(device, snaplen,promiscuous,to_ms,error);
    if(handle == NULL) 
    {
        fprintf (stderr, "Couln't open device %s: %s\n", device, error);
        return 2;
    }
    if(pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf (stderr, "Device %s doesn't provide Ethernet headers\n",device);
        return 2;
    }

    /** Filtering traffic*/
    if (pcap_compile(handle, &fp, filter_exp,optimize,mask) == -1)
    {
        fprintf (stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if(pcap_setfilter (handle,&fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    /** capture a single packet*/
    packet = pcap_next(handle, &header);
	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */
	pcap_close(handle);
	return 2;



    return 1;


}
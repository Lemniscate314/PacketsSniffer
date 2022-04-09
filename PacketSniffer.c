#include <stdio.h>
#include <pcap.h>
/***/
int main (int args, char **argv)
{
    char *device = argv[1];
    char error_lookup [PCAP_ERRBUF_SIZE];
    /*find a device*/
    device = pcap_lookupdev (error_lookup);
    if(device == NULL)
    {
        printf("Any default device found: %s\n", error_lookup);
        return 0;
    }
    return 1;


}
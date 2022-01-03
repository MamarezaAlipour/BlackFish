#ifdef OS_AIX
#include <string.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pcap.h>
#include <fcntl.h>
#include <string.h>

#include <netz.h>

#include "version.h"
#include "support.h"
#include "ph_packet.h"
#include "help.h"

extern int opterr;
extern int optind;

bool filter_from_file = false;
char filter_file[64];
bool debug_mode = false;
bool screen_output = true;
bool file_output = false;
int output_file;
bool hide_ether_loopback = false;
bool hide_cisco_cdp = false;
bool hide_eigrp_hello = false;
bool hide_ospf_hello = false;

string pcap_filter[2048] = "";

void print_version_info()
{
    message((char *)"BLACKFISH version %s, build date %s\n",
            BFISH_VERSION, BFISH_BUILD_DATE);

    char netz_version_string[32];
    char netz_build_date_string[32];

    message((char *)"NETZ version %s, build date %s\n",
            netz_version(netz_version_string),
            netz_build_date(netz_build_date_string));
}

int open_output_file(string *filename)
{
    output_file = open(filename, O_RDWR | O_CREAT | O_APPEND, 400);

    if (output_file < 0)
    {
        return -1;
    }

    return 0;
}

void print_help()
{
    printf("%s", help_string);
}

int pcap_init(string *interface, bool promisc, u_int cap_len)
{
    string errbuf[PCAP_ERRBUF_SIZE];
    int retval;

    pcap_t *pcap = pcap_open_live(interface, cap_len, promisc, 1024, errbuf);

    if (pcap == NULL)
    {
        message((char *)"interface open failed: %s\n", errbuf);
        return -1;
    }

    int linklayer = pcap_datalink(pcap);

    if (pcap < 0)
    {
        message((char *)"pcap_datalink failed: %s\n", errbuf);
        return -1;
    }
    else
    {
        message((char *)"link type: ");

        switch (linklayer)
        {
        case DLT_NULL:
            message((char *)"no link-layer encapsulation (gif)\n");
            break;

        case DLT_EN10MB:
            message((char *)"Ethernet\n");
            break;

        case DLT_EN3MB:
            message((char *)"Experimental Ethernet (3Mb) [not supported]\n");
            return -1;

        case DLT_AX25:
            message((char *)"Amateur Radio AX.25 [not supported]\n");
            return -1;

        case DLT_PRONET:
            message((char *)"Proteon ProNET Token Ring [not supported]\n");
            return -1;

        case DLT_CHAOS:
            message((char *)"Chaos [not supported]\n");
            return -1;

        case DLT_IEEE802:
            message((char *)"IEEE 802 Networks [not supported]\n");
            return -1;

        case DLT_ARCNET:
            message((char *)"Arcnet [not supported]\n");
            return -1;

        case DLT_SLIP:
            message((char *)"Serial Line IP [not supported]\n");
            return -1;

        case DLT_PPP:
            message((char *)"Point-to-Point Protocol [not supported]\n");
            return -1;

        case DLT_FDDI:
            message((char *)"FDDI [not supported]\n");
            return -1;

        case DLT_ATM_RFC1483:
            message((char *)"LLC/SNAM Encapsulated atm [not supported]\n");
            return -1;

#ifdef OS_OPENBSD
        case DLT_LOOP:
            message((char *)"loopback type (af header)\n");
            break;

        case DLT_ENC:
            message((char *)"IPSEC enc type\n");
            break;
#endif

        case DLT_RAW:
            message((char *)"raw IP [not supported]\n");
            return -1;

        case DLT_SLIP_BSDOS:
            message((char *)"BSD/OS Serial Line IP [not supported]\n");
            return -1;

        case DLT_PPP_BSDOS:
            message((char *)"BSD/OS Point-to-Point Protocol [not supported]\n");
            return -1;

        default:
            message((char *)"unidentified\n");
            return -1;
        }
    }

    dword localnet = 0;
    dword netmask = 0;

    retval = pcap_lookupnet(interface, &localnet, &netmask, errbuf);

    if (retval < 0)
    {
        message((char *)"interface %s has no IPV4 address assigned\n", interface);
    }
    else
    {
        string localnet_string[16];
        string netmask_string[16];

        conv_ip_str(localnet_string, localnet);
        conv_ip_str(netmask_string, netmask);

        message((char *)"localnet: %s\n", localnet_string);
        message((char *)"netmask: %s\n", netmask_string);
    }

    message((char *)"hiden packets: ");

    if (hide_ether_loopback)
    {
        message((char *)"ether loopback; ");
    }

    if (hide_cisco_cdp)
    {
        message((char *)"cisco cdp; ");
    }

    if (hide_eigrp_hello)
    {
        message((char *)"eigrp hello; ");
    }

    if (hide_ospf_hello)
    {
        message((char *)"ospf hello; ");
    }

    message((char *)"\n");

    message((char *)"pcap filter: '%s'\n", pcap_filter);

    bpf_program filtercode;

    retval = pcap_compile(pcap, &filtercode, pcap_filter, 1, netmask);

    if (retval < 0)
    {
        message((char *)"filter compiling failed: %s\n", pcap_geterr(pcap));
        return -1;
    }
    else
    {
        message((char *)"filter compiled...\n");
    }

    retval = pcap_setfilter(pcap, &filtercode);

    if (retval < 0)
    {
        message((char *)"filter setting failed: %s\n", pcap_geterr(pcap));
        return -1;
    }
    else
    {
        message((char *)"filter applied...\n");
    }

    message((char *)"capturing started...\n\n");

    pcap_loop(pcap, -1, (pcap_handler)packet_handler, (byte *)&linklayer);

    return 0;
}

int main(int argc, char **argv)
{
    char bfish_build_date[64];

    strncpy(bfish_build_date, BFISH_BUILD_DATE, 64);

    message((char *)"BLACKFISH %s (c) 2021-%s Parisa Khaleghi\n",
            BFISH_VERSION, bfish_build_date + strlen(bfish_build_date) - 4);

    string interface[16] = "none";
    bool promisc = true;
    u_int cap_len = 0;

    int retval;
    int option;

    opterr = 1;

    while ((option = getopt(argc, argv, "dvi:pF:c:ho:O:H:")) != -1)
    {
        switch (option)
        {
        case 'd':
            debug_mode = true;
            break;

        case 'v':
            print_version_info();
            return 0;

        case 'i':
            snprintf(interface, 16, "%s", optarg);
            break;

        case 'o':
            retval = open_output_file(optarg);

            if (retval)
            {
                message((char *)"cannot open or create output file: %s\n", optarg);
                return -1;
            }

            file_output = true;

            break;

        case 'O':
            retval = open_output_file(optarg);

            if (retval)
            {
                message((char *)"cannot open or create output file: %s\n", optarg);
                return -1;
            }

            file_output = true;
            screen_output = false;

            break;

        case 'p':
            promisc = false;
            break;

        case 'F':
            filter_from_file = true;
            strncpy(filter_file, optarg, 64);
            break;

        case 'c':
            cap_len = atoi(optarg);
            break;

        case 'h':
            print_help();
            return 0;

        case 'H':
            if (!strcmp(optarg, "el"))
            {
                hide_ether_loopback = true;
            }
            else if (!strcmp(optarg, "cdp"))
            {
                hide_cisco_cdp = true;
            }
            else if (!strcmp(optarg, "eigrp_hello"))
            {
                hide_eigrp_hello = true;
            }
            else if (!strcmp(optarg, "ospf_hello"))
            {
                hide_ospf_hello = true;
            }
            else
            {
                message((char *)"bad hide argument: %s\n", optarg);
                return -1;
            }
            break;

        case '?':
            return -1;
        }
    }

    if (filter_from_file)
    {
        int file = open(filter_file, O_RDONLY);

        if (file < 0)
        {
            message((char *)"cannot open filter file: %s\n", filter_file);
            return -1;
        }

        read(file, pcap_filter, 2048);
        close(file);
    }
    else
    {
        if (argv[optind])
            argvncpy(pcap_filter, &argv[optind], 256);
    }

    if (debug_mode)
    {
        message((char *)"debug mode\n");
    }

    if (screen_output)
    {
        message((char *)"screen output mode: ON\n");
    }
    else
    {
        message((char *)"screen output mode: OFF\n");
    }

    if (file_output)
    {
        message((char *)"file output mode: ON\n");
    }
    else
    {
        message((char *)"file output mode: OFF\n");
    }

    if (strcmp(interface, "none"))
    {
        message((char *)"interface: %s\n", interface);

        ifreq ifr;
        strncpy(ifr.ifr_name, interface, 8);

        int sock = socket(AF_INET, SOCK_DGRAM, 0);

        if (ioctl(sock, SIOCGIFMTU, (caddr_t)&ifr) < 0)
        {
            message((char *)"%s mtu discovery failed...\n", interface);
            return -1;
        }
        else
        {
            u_int mtu = ifr.ifr_mtu;

            message((char *)"mtu: %u\n", mtu);

            if (!cap_len)
            {
                cap_len = mtu + 32;
            }
        }
    }
    else
    {
        message((char *)"interface not set...\n", interface);
        return -1;
    }

    if ((cap_len > 0) && (cap_len < 65536))
    {
        message((char *)"capture length: %u\n", cap_len);
    }
    else
    {
        message((char *)"wrong capture length set, can be 1 - 65535\n");
        return -1;
    }

    if (promisc)
    {
        message((char *)"promisc mode: ON\n");
    }
    else
    {
        message((char *)"promisc mode: OFF\n");
    }

    return pcap_init(interface, promisc, cap_len);
}

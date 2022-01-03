#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string print_ipx_socket(word);
c_string print_ipx_ptype(byte);

c_string ipx_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_ipx_header header(packet_info.packet);

    output_string.add((char *)"IPX\t");

    string node_str[32];

    output_string.add((char *)"SNODE %s ",
                      conv_ipx_str(node_str, header.get_snode()));

    output_string.add((char *)"DNODE %s  ",
                      conv_ipx_str(node_str, header.get_dnode()));

    output_string.add((char *)"CKSUM %u\n",
                      header.get_cksum());

    output_string.add((char *)"\tSNET %08u  DNET %08u  ",
                      header.get_snet(),
                      header.get_dnet());

    output_string.add((char *)"LEN %u  TCTRL %u\n",
                      header.get_len(),
                      header.get_tcontrol());

    output_string.add((char *)"\tSSOCK %u (",
                      header.get_ssock());

    output_string += print_ipx_socket(header.get_ssock());

    output_string.add((char *)")  DSOCK %u (",
                      header.get_dsock());

    output_string += print_ipx_socket(header.get_dsock());

    output_string.add_hex((char *)")  PTYPE 0x%02X (",
                          header.get_ptype());

    output_string += print_ipx_ptype(header.get_ptype());

    output_string.add((char *)")\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}

c_string print_ipx_ptype(byte ptype)
{
    switch (ptype)
    {
    case IPX_TYPE_UNKNOWN:
        return c_string((char *)"SAP or RIP");

    case IPX_TYPE_RIP:
        return c_string((char *)"RIP");

    case IPX_TYPE_SPX:
        return c_string((char *)"SPX/SPXII");

    case IPX_TYPE_NCP:
        return c_string((char *)"NCP");

    case IPX_TYPE_NETBIOS:
        return c_string((char *)"NetBIOS");

    default:
        return c_string((char *)"Unknown");
    }
}

c_string print_ipx_socket(word socket)
{
    switch (socket)
    {
    case IPX_SOCKET_ECHO:
        return c_string((char *)"Echo");

    case IPX_SOCKET_ERROR:
        return c_string((char *)"Error");

    case IPX_SOCKET_NVT:
        return c_string((char *)"NVT");

    case IPX_SOCKET_NCP:
        return c_string((char *)"NCP");

    case IPX_SOCKET_SAP:
        return c_string((char *)"SAP");

    case IPX_SOCKET_RIP:
        return c_string((char *)"RIP");

    case IPX_SOCKET_NETBIOS:
        return c_string((char *)"NetBIOS");

    case IPX_SOCKET_NDP:
        return c_string((char *)"NDP");

    case IPX_SOCKET_SERIAL:
        return c_string((char *)"Serial");

    case IPX_SOCKET_NVT2:
        return c_string((char *)"NVT2");

    case IPX_SOCKET_PRINT:
        return c_string((char *)"Print");

    default:
        return c_string((char *)"Unknown");
    }
}

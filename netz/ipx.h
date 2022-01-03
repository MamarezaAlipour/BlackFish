#ifndef _NETZ_IPX_H_
#define _NETZ_IPX_H_

#include "support.h"

/*
 * Structure of an IPX header (RFC ???)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Packet Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Tcontrol   |     Ptype     |      Destination Network
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        Destination Network      |  Dest Node 0  |  Dest Node 1  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Dest Node 2  |  Dest Node 3  |  Dest Node 4  |  Dest Node 5  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Destination Socket       |         Source Network
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *           Source Network        |  Src Node 0   |  Src Node 1   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Src Node 2   |  Src Node 3   |  Src Node 4   |  Src Node 5   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Source Socket         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#pragma pack(1)

struct s_ipx_header
{
    word cksum;    /* checksum */
    word len;      /* packet length */
    byte tcontrol; /* */
    byte ptype;    /* protocol type */
    dword dnet;    /* destination network */
    byte dnode[6]; /* destination node */
    word dsock;    /* destination socket */
    dword snet;    /* source network */
    byte snode[6]; /* source node */
    word ssock;    /* source socket */
};

#pragma pack(4)

#define IPX_HEADER_LEN sizeof(s_ipx_header)

/*
 * Type definitions (type)
 */

#define IPX_TYPE_UNKNOWN 0x00 /* unknown packet type (SAP or RIP) */
#define IPX_TYPE_RIP 0x01     /* routing information packet (RIP) */
#define IPX_TYPE_SPX 0x05     /* sequenced packet (SPX/SPXII) */
#define IPX_TYPE_NCP 0x11     /* NetWare core protocol (NCP) */
#define IPX_TYPE_NETBIOS 0x14 /* NetBIOS broadcast */

/*
 * Socket definitions (ssock, dsock)
 */

#define IPX_SOCKET_ECHO 0x0002    /* Echo protocol socket */
#define IPX_SOCKET_ERROR 0x0003   /* Error handler packet */
#define IPX_SOCKET_NVT 0x0247     /* Novell Virtual Terminal server */
#define IPX_SOCKET_NCP 0x0451     /* NetWare Core Protocol */
#define IPX_SOCKET_SAP 0x0452     /* NetWare Service Advertising \
                                         Protocol (SAP) */
#define IPX_SOCKET_RIP 0x0453     /* NetWare Routing Protocol (RIP) */
#define IPX_SOCKET_NETBIOS 0x0455 /* NetBIOS */
#define IPX_SOCKET_NDP 0x0456     /* NetWare Diagnostics Protocol */
#define IPX_SOCKET_SERIAL 0x0457  /* Serialization packet */
#define IPX_SOCKET_NVT2 0x8063    /* NVT2 Server */
#define IPX_SOCKET_PRINT 0x811E   /* Print Server */

#endif /* _NETZ_IPX_H_ */

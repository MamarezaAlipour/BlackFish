#ifndef _NETZ_ETHER_TYPE_H_
#define _NETZ_ETHER_TYPE_H_

/*
 * Protocol types used in 'ether_type' field by Ethernet and in 'snap_type'
 * by SNAP frame
 */

#define ETHER_TYPE_MIN 0x0600         /* minimal value of ether_type field */
#define ETHER_TYPE_IDP 0x0600         /* XEROX NS IDP */
#define ETHER_TYPE_IP 0x0800          /* IPv4 protocol */
#define ETHER_TYPE_X75 0x0801         /* X.75 Internet */
#define ETHER_TYPE_NBS 0x0802         /* NBS Internet */
#define ETHER_TYPE_ECMA 0x0803        /* ECMA Internet */
#define ETHER_TYPE_CHAOS 0x0804       /* Chaosnet */
#define ETHER_TYPE_X25 0x0805         /* X.25 Level 3 */
#define ETHER_TYPE_ARP 0x0806         /* address resolution protocol */
#define ETHER_TYPE_XNS 0x0807         /* XNS Compatibility */
#define ETHER_TYPE_XPUP 0x0A00        /* Xerox IEEE802.3 PUP */
#define ETHER_TYPE_DECNET 0x6003      /* DEC DECNET Phase IV Route */
#define ETHER_TYPE_EXCELAN 0x8010     /* Excelan */
#define ETHER_TYPE_SGI 0x8014         /* SGI network games */
#define ETHER_TYPE_REVARP 0x8035      /* reverse addr resolution protocol */
#define ETHER_TYPE_UM 0x8066          /* Univ. of Mass. @ Amherst */
#define ETHER_TYPE_ATT 0x8069         /* AT&T */
#define ETHER_TYPE_APPLETALK 0x809B   /* Appletalk */
#define ETHER_TYPE_BANYAN_80C4 0x80C4 /* Banyan Systems */
#define ETHER_TYPE_BANYAN_80C5 0x80C5 /* Banyan Systems */
#define ETHER_TYPE_IBMSNA 0x80D5      /* IBM SNA Service on Ethernet */
#define ETHER_TYPE_AARP 0x80F3        /* AppleTalk AARP (Kinetics) */
#define ETHER_TYPE_APOLLO 0x80F7      /* Apollo Computer */
#define ETHER_TYPE_8021Q 0x8100       /* IEEE 802.1Q VLAN tagging */
#define ETHER_TYPE_BRIDGE_8132 0x8132 /* Bridge Communications */
#define ETHER_TYPE_BRIDGE_8133 0x8133 /* Bridge Communications */
#define ETHER_TYPE_BRIDGE_8134 0x8134 /* Bridge Communications */
#define ETHER_TYPE_BRIDGE_8135 0x8135 /* Bridge Communications */
#define ETHER_TYPE_BRIDGE_8136 0x8136 /* Bridge Communications */
#define ETHER_TYPE_IPX 0x8137         /* Novell, Inc. IPX protocol*/
#define ETHER_TYPE_NOVELL_8138 0x8138 /* Novell, Inc. */
#define ETHER_TYPE_SNMP 0x814C        /* SNMP */
#define ETHER_TYPE_ASCOM 0x8222       /* Ascom Banking Systems */
#define ETHER_TYPE_AES_823E 0x823E    /* Advanced Encryption Systems */
#define ETHER_TYPE_AES_823F 0x823F    /* Advanced Encryption Systems */
#define ETHER_TYPE_AES_8240 0x8240    /* Advanced Encryption Systems */
#define ETHER_TYPE_IP6 0x86DD         /* IPv6 protocol */
#define ETHER_TYPE_PPPOEDISC 0x8863   /* PPP Over Ethernet Discovery Stage */
#define ETHER_TYPE_PPPOE 0x8864       /* PPP Over Ethernet Session Stage */
#define ETHER_TYPE_LOOPBACK 0x9000    /* used to test interfaces */
#define ETHER_TYPE_BBN 0xFF00         /* BBN VITAL-LanBridge cache */

/*
 * Protocol types used in 'snap_type' by SNAP frame
 */

#define SNAP_TYPE_CDP 0x2000 /* cisco discovery protocol */

#endif /* _NETZ_ETHER_TYPE_H_ */

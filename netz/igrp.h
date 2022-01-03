#ifndef _NETZ_IGRP_H_
#define _NETZ_IGRP_H_

#include "types.h"

/*
 * Structure of an IGRP header (Cisco)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version| Opcode|    Edition    |              ASN              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Ninterior           |            Nsystem            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Nexterior           |             Cksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_igrp_header
{
        byte vo;       /* version and opcode */
        byte edition;  /* edition number */
        word as;       /* Autonomous System Number */
        word interior; /* number of subnets in local net */
        word system;   /* number of networks in AS */
        word exterior; /* number of networks in outside AS */
        word cksum;    /* checksum */
};

#define IGRP_HEADER_LEN sizeof(s_igrp_header)

/*
 * Masks for header length and version
 */

#define IGRP_VO_VER_MASK 0xF0
#define IGRP_VO_OPCODE_MASK 0x0F

/*
 * Opcodes
 */

#define IGRP_OPCODE_UPDATE 0x01
#define IGRP_OPCODE_REQUEST 0x02

/*
 * Structure of an IGRP route update (Cisco)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Number                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       Delay                     |               Bandwidth
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                 |              MTU              |  Reliability  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Load      |    Hopcount   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#pragma pack(1)

struct s_igrp_update
{
        byte number[3];    /* first or last three octets of IP address */
        byte delay[3];     /* delay */
        byte bandwidth[3]; /* bandwidth */
        word mtu;          /* number of subnets in local net */
        byte reliability;  /* number of networks in AS */
        byte load;         /* number of networks in outside AS */
        byte hopcount;     /* hopcount */
};

#pragma pack(4)

#define IGRP_UPDATE_LEN sizeof(s_igrp_update)

#endif /* _NETZ_IGRP_H_ */

#ifndef _NETZ_IGMP_H_
#define _NETZ_IGMP_H_

#include "types.h"

/*
 * IGMP packet format.
 */

struct s_igmp_header
{
    byte type;   /* version & type of IGMP message  */
    byte code;   /* code for routing sub-messages   */
    word cksum;  /* IP-style checksum               */
    dword group; /* group address being reported    */
};

#define IGMP_HEADER_LEN sizeof(s_igmp_header)

#define IGMP_HOST_MEMBERSHIP_QUERY 0x11     /* membership query      */
#define IGMP_V1_HOST_MEMBERSHIP_REPORT 0x12 /* v1 membership report  */
#define IGMP_DVMRP 0x13                     /* DVMRP routing message */
#define IGMP_PIM 0x14                       /* PIM routing message   */
#define IGMP_V2_HOST_MEMBERSHIP_REPORT 0x16 /* v2 membership report  */
#define IGMP_HOST_LEAVE_MESSAGE 0x17        /* leave-group message   */
#define IGMP_MTRACE_REPLY 0x1e              /* traceroute reply      */
#define IGMP_MTRACE_QUERY 0x1f              /* traceroute query      */

#define IGMP_DELAYING_MEMBER 1
#define IGMP_IDLE_MEMBER 2
#define IGMP_LAZY_MEMBER 3
#define IGMP_SLEEPING_MEMBER 4
#define IGMP_AWAKENING_MEMBER 5

#endif /* _NETZ_IGMP_H_ */

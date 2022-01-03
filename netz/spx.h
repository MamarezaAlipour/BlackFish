#ifndef _NETZ_SPX_H_
#define _NETZ_SPX_H_

#include "support.h"

/*
 * Structure of an SPX header (RFC ???)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    CCFflags   |     DType     |      Soure Connection ID      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Destination Connection ID   |        Sequence Number        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Acknowledge Number       |       Allocation Number       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_spx_header
{
    byte ccflags; /* connection control flags */
    byte dtype;   /* datastream type */
    word srcid;   /* source connection id */
    word dstid;   /* destination connection id */
    word seq;     /* sequence number */
    word ack;     /* acknowledge number */
    word alloc;   /* allocation number */
};

#define SPX_HEADER_LEN sizeof(s_spx_header)

/*
 * Flags for connection control definitions (ccflags)
 */

#define SPX_CCFLAGS_EOM 0x10 /* end of message */
#define SPX_CCFLAGS_ACK 0x40 /* request of this packet receipt ack */
#define SPX_CCFLAGS_SYS 0x80 /* system packet */

/*
 * Datastream type definitins (dtype)
 */

#define SPX_DTYPE_EOC 0xFE  /* end of connection */
#define SPX_DTYPE_EOCA 0xFF /* end of connection acknowledge */

#endif /* _NETZ_SPX_H_ */

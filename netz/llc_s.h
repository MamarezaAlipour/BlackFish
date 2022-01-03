#ifndef _NETZ_LLC_S_H_
#define _NETZ_LLC_S_H_

#include "types.h"

/*
 * IEEE 802.2 LLC (Logical Link Control) S-format header
 */

/*
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     DSAP      |     SSAP      |X X X X|S S|0 1|     N(R)    |P|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_llc_s_header
{
    byte dsap; /* destiantion service access point */
    byte ssap; /* source service access point */
    word ctrl; /* control*/
};

#define LLC_S_HEADER_LEN sizeof(s_llc_s_header)

/*
 * Control field masks and values
 */

#define LLC_S_ID_MASK 0x0300 /* ID mask */
#define LLC_S_ID 1           /* ID value */
#define LLC_S_S_MASK 0x0C00  /* S mask */
#define LLC_S_S_RR 0x00      /* Receive Ready */
#define LLC_S_S_RNR 0x80     /* Receive Not Ready */
#define LLC_S_S_REJ 0x40     /* Reject */
#define LLC_S_PF_MASK 0x0001 /* P/F mask */
#define LLC_S_NR_MASK 0x00FE /* N(R) mask  */

/*
 * Definitions common for all LLC formats
 */

#include "llc.h"

#endif /* _NETZ_LLC_S_H_ */

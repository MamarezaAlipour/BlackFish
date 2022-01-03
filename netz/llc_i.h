#ifndef _NETZ_LLC_I_H_
#define _NETZ_LLC_I_H_

#include "types.h"

/*
 * IEEE 802.2 LLC (Logical Link Control) I-format header
 */

/*
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     DSAP      |     SSAP      |    N(S)     |0|     N(R)    |P|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_llc_i_header
{
    byte dsap; /* destiantion service access point */
    byte ssap; /* source service access point */
    word ctrl; /* control*/
};

#define LLC_I_HEADER_LEN sizeof(s_llc_i_header)

/*
 * Control field masks and values
 */

#define LLC_I_ID_MASK 0x0100 /* ID mask */
#define LLC_I_ID 0           /* ID value */
#define LLC_I_NS_MASK 0xFE00 /* N(S) mask */
#define LLC_I_PF_MASK 0x0001 /* P/F mask */
#define LLC_I_NR_MASK 0x00FE /* N(R) mask */

/*
 * Definitions common for all LLC formats
 */

#include "llc.h"

#endif /* _NETZ_LLC_I_H_ */

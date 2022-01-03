#ifndef _NETZ_LLC_U_H_
#define _NETZ_LLC_U_H_

#include "types.h"

/*
 * IEEE 802.2 LLC (Logical Link Control) U-format header
 */

/*
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     DSAP      |     SSAP      |M M M|P|M M|1 1|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#pragma pack(1)

struct s_llc_u_header
{
    byte dsap; /* destiantion service access point */
    byte ssap; /* source service access point */
    byte ctrl; /* control*/
};

#pragma pack(4)

#define LLC_U_HEADER_LEN sizeof(s_llc_u_header)

/*
 * Control field masks and values
 */

#define LLC_U_ID_MASK 0x03 /* ID mask */
#define LLC_U_ID 3         /* ID value */
#define LLC_U_PF_MASK 0x10 /* P/F mask */
#define LLC_U_M_MASK 0xEC  /* M bits mask including P/F as zero */
#define LLC_U_M_UI 0x00    /* unnumbered information */
#define LLC_U_M_SABME 0x6C /* set asynchronous balanced mode */
#define LLC_U_M_DISC 0x40  /* disconnect */
#define LLC_U_M_UA 0x60    /* unnumbered acknowledgement */
#define LLC_U_M_DM 0x0C    /* disconnected mode */
#define LLC_U_M_FRMR 0x84  /* frame reject */
#define LLC_U_M_XID 0xAC   /* exchange identification */
#define LLC_U_M_TEST 0xE0  /* test */

/*
 * Definitions common for all LLC formats
 */

#include "llc.h"

#endif /* _NETZ_LLC_U_H_ */

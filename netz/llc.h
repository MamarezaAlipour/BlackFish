#ifndef _NETZ_LLC_H_
#define _NETZ_LLC_H_

/*
 * LLC DSAP field bit masks
 */

#define LLC_DSAP_ADDR_MASK 0xFC /* DSAP main address part mask */
#define LLC_DSAP_ISO_MASK 0x02  /* DSAP ISO bit mask */
#define LLC_DSAP_IG_MASK 0x01   /* individual/group bit mask */

/*
 * LLC SSAP fiels bit masks
 */

#define LLC_SSAP_CR_MASK 0x01   /* command/request bit mask */
#define LLC_SSAP_ADDR_MASK 0xFE /* SSAP main address part mask */

/*
 * SAP values
 */

#define LLC_SAP_NLSAP 0x00   /* Null LSAP */
#define LLC_SAP_ILSM 0x02    /* Individual LLC Sublayer Mgt */
#define LLC_SAP_GLSM 0x03    /* Group LLC Sublayer Mgt */
#define LLC_SAP_SNAPC 0x04   /* SNA Path Control */
#define LLC_SAP_DODIP 0x06   /* DoD IP */
#define LLC_SAP_PLAN_0E 0x0E /* PROWAY-LAN */
#define LLC_SAP_EIA 0x4E     /* EIA-RS 511 */
#define LLC_SAP_ISIIP 0x5E   /* ISI IP */
#define LLC_SAP_3COM 0x80    /* 3Com */
#define LLC_SAP_PLAN_8E 0x8E /* PROWAY-LAN */
#define LLC_SAP_SNAP 0xAA    /* SNAP */
#define LLC_SAP_BC 0xBC      /* Banyan */
#define LLC_SAP_NOVELL 0xE0  /* Novell */
#define LLC_SAP_NETBEUI 0xF0 /* NetBEUI */
#define LLC_SAP_LANMAN 0xF4  /* Lan Manager */
#define LLC_SAP_CLNS 0xFE    /* ISO CLNS IS 8473 */
#define LLC_SAP_GLOBAL 0xFF  /* Global DSAP */

#endif /* _NETZ_LLC_H_ */

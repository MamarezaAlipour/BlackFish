#ifndef _NETZ_ESP_H_
#define _NETZ_ESP_H_

/*
 * Structure of an ESP packet (RFC 2406)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
 * |               Security Parameters Index (SPI)                 | ^Auth.
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
 * |                      Sequence Number                          | |erage
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
 * |                    Payload Data* (variable)                   | |   ^
 * ~                                                               ~ |   |
 * |                                                               | |Conf.
 * +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
 * |               |     Padding (0-255 bytes)                     | |erage*
 * +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
 * |                               |  Pad Length   | Next Header   | v   v
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
 * |                 Authentication Data (variable)                |
 * ~                                                               ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#include "types.h"

struct s_esp_header
{
	dword spi; /* SPI */
	dword seq; /* sequence number */
};

#define ESP_HEADER_LEN sizeof(s_esp_header)

#endif /* _NETZ_ESP_H_ */

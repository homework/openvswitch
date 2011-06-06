#ifndef HWDB_DEBUG_H
#define HWDB_DEBUG_H

#ifndef HWDB_VERBOSE
#define HWDB_VERBOSE /* enables debug messages */
#endif

#undef HWDB_VERBOSE /* disable debug messages */

#undef dbg
#ifdef HWDB_VERBOSE
#	ifdef __KERNEL__
#		define dbg(fmt, args...) printk(KERN_DEBUG "[hwdb] " fmt, ## args)
#	else
#		define dbg(fmt, args...) fprintf(stderr, fmt, ## args)
#	endif
#else
#	define dbg(fmt, args...)
#endif

#define ETH_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define ETH_ARG(e) (e)[0], (e)[1], (e)[2], (e)[3], (e)[4], (e)[5]

#define IP4_FMT "%u.%u.%u.%u"

#define IP4_ARG(ip) \
	((void) (ip)[0], ((uint8_t *) ip)[0]), \
	((uint8_t *) ip)[1], \
	((uint8_t *) ip)[2], \
	((uint8_t *) ip)[3]

#define FIN 0x01 /* TCP flags */
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80

#define FLG_FMT "%s%s%s%s%s%s%s%s"

#define FLG_ARG(flags) \
	(flags & ACK) ? ":ACK" : "", \
	(flags & SYN) ? ":SYN" : "", \
	(flags & RST) ? ":RST" : "", \
	(flags & PSH) ? ":PSH" : "", \
	(flags & FIN) ? ":FIN" : "", \
	(flags & URG) ? ":URG" : "", \
	(flags & ECE) ? ":ECE" : "", \
	(flags & CWR) ? ":CWR" : ""

#endif /* debug.h */

// CNetInfo — reads the Mac's own IPv4 address table (IP → hardware address) in-process,
// through the same kernel call the `arp` tool uses. Read-only; sends nothing on the network.

#ifndef CNETINFO_H
#define CNETINFO_H

typedef struct {
    char ip[16];              // dotted IPv4, NUL-terminated
    unsigned char mac[6];
} wn_arp_entry;

/// Fills `out` with up to `max` entries that have a hardware address.
/// Returns the number written (>= 0), or -errno if the kernel refused.
/// `*total` receives how many table records the kernel returned (with or without an address).
int wn_arp_entries(wn_arp_entry *out, int max, int *total);

typedef struct {
    char dest[46];            // "default" shows as 0.0.0.0
    char gateway[46];         // IPv4, or "link#N" for directly connected
    char netmask[46];
    char ifname[17];
    unsigned int flags;       // RTF_* flags
} wn_route;

/// Fills `out` with up to `max` IPv4 routes. Returns the number written (>= 0) or -errno.
int wn_routes(wn_route *out, int max, int *total);

#endif

// In-process read of the IPv4 routing table: sysctl(NET_RT_DUMP), the same data `netstat -rn`
// prints. Read-only — WiSecured never adds, changes or deletes a route.

#include "CNetInfo.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WN_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

/// Writes a printable form of one routing-message address into `out`.
static void describe(const struct sockaddr *sa, int is_mask, char *out, size_t size) {
    out[0] = '\0';
    if (sa->sa_family == AF_INET || (is_mask && sa->sa_len <= sizeof(struct sockaddr_in))) {
        // Netmasks can be shortened: only the first sa_len bytes are present.
        struct in_addr addr = { 0 };
        size_t present = sa->sa_len > 4 ? (size_t)sa->sa_len - 4 : 0;
        if (present > sizeof addr) present = sizeof addr;
        memcpy(&addr, (const char *)sa + 4, present);
        inet_ntop(AF_INET, &addr, out, (socklen_t)size);
    } else if (sa->sa_family == AF_LINK) {
        const struct sockaddr_dl *sdl = (const struct sockaddr_dl *)sa;
        snprintf(out, size, "link#%d", sdl->sdl_index);
    }
}

int wn_routes(wn_route *out, int max, int *total) {
    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0 };
    size_t needed = 0;
    *total = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) return -errno;
    if (needed == 0) return 0;

    char *buf = malloc(needed);
    if (!buf) return -ENOMEM;
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
        int err = errno;
        free(buf);
        return -err;
    }

    int written = 0;
    char *end = buf + needed;
    for (char *next = buf; next + sizeof(struct rt_msghdr) <= end; ) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)next;
        if (rtm->rtm_msglen == 0 || next + rtm->rtm_msglen > end) break;
        (*total)++;

        if (written < max) {
            wn_route *r = &out[written];
            memset(r, 0, sizeof *r);
            r->flags = (unsigned int)rtm->rtm_flags;
            if (!if_indextoname(rtm->rtm_index, r->ifname)) r->ifname[0] = '\0';

            char *p = (char *)(rtm + 1);
            char *msg_end = next + rtm->rtm_msglen;
            for (int bit = 0; bit < RTAX_MAX && p < msg_end; bit++) {
                if (!(rtm->rtm_addrs & (1 << bit))) continue;
                struct sockaddr *sa = (struct sockaddr *)p;
                if (bit == RTAX_DST) describe(sa, 0, r->dest, sizeof r->dest);
                else if (bit == RTAX_GATEWAY) describe(sa, 0, r->gateway, sizeof r->gateway);
                else if (bit == RTAX_NETMASK) describe(sa, 1, r->netmask, sizeof r->netmask);
                p += WN_ROUNDUP(sa->sa_len);
            }
            if (r->dest[0]) written++;
        }
        next += rtm->rtm_msglen;
    }
    free(buf);
    return written;
}

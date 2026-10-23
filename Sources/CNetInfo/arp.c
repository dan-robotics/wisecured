// In-process read of the IPv4 address table: sysctl(NET_RT_FLAGS, RTF_LLINFO), parsed the
// same way as macOS' own arp(8). Read-only.

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
#include <stdlib.h>
#include <string.h>

// Socket addresses in routing messages are padded to 4-byte boundaries.
#define WN_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

int wn_arp_entries(wn_arp_entry *out, int max, int *total) {
    // Family 0 (all): on macOS 27 asking for AF_INET only returns an empty table.
    int mib[6] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_FLAGS, RTF_LLINFO };
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

        struct sockaddr_in *sin = (struct sockaddr_in *)(rtm + 1);
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)((char *)sin + WN_ROUNDUP(sin->sin_len));
        if (written < max && (char *)sdl + sizeof(struct sockaddr_dl) <= next + rtm->rtm_msglen &&
            sin->sin_family == AF_INET && sdl->sdl_family == AF_LINK && sdl->sdl_alen == 6) {
            if (inet_ntop(AF_INET, &sin->sin_addr, out[written].ip, sizeof out[written].ip)) {
                memcpy(out[written].mac, LLADDR(sdl), 6);
                written++;
            }
        }
        next += rtm->rtm_msglen;
    }
    free(buf);
    return written;
}

/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "ovn-util.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-nb-idl.h"
#include "ovn/lib/ovn-sb-idl.h"

VLOG_DEFINE_THIS_MODULE(ovn_util);

static void
init_lpa(struct lport_addresses *lpa)
{
    lpa->n_ipv4_addrs = 0;
    lpa->n_ipv6_addrs = 0;
    lpa->ipv4_addrs = NULL;
    lpa->ipv6_addrs = NULL;
    lpa->ea_s = NULL;
}

static void
set_ipv4_netaddr(uint32_t addr, unsigned int plen, struct ipv4_netaddr *netaddr)
{
    netaddr->addr = addr;
    netaddr->mask = be32_prefix_mask(plen);
    netaddr->network = addr & netaddr->mask;
    netaddr->plen = plen;

    netaddr->addr_s = xasprintf(IP_FMT, IP_ARGS(addr));
    netaddr->network_s = xasprintf(IP_FMT, IP_ARGS(netaddr->network));
    netaddr->bcast_s = xasprintf(IP_FMT, IP_ARGS(addr | ~netaddr->mask));
}

static void
set_ipv6_netaddr(struct in6_addr addr, unsigned int plen,
                 struct ipv6_netaddr *netaddr)
{
    memcpy(&netaddr->addr, &addr, sizeof(struct in6_addr));
    netaddr->mask = ipv6_create_mask(plen);
    netaddr->network = ipv6_addr_bitand(&addr, &netaddr->mask);
    netaddr->plen = plen;
    in6_addr_solicited_node(&netaddr->sn_addr, &addr);

    netaddr->addr_s = xmalloc(INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &addr, netaddr->addr_s, INET6_ADDRSTRLEN);
    netaddr->sn_addr_s = xmalloc(INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &netaddr->sn_addr, netaddr->sn_addr_s,
              INET6_ADDRSTRLEN);
    netaddr->network_s = xmalloc(INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &netaddr->network, netaddr->network_s,
              INET6_ADDRSTRLEN);
}

/*
 * Extracts the mac, ipv4 and ipv6 addresses from the input param 'address'
 * which should be of the format 'MAC [IP1 IP2 ..]" where IPn should be
 * a valid IPv4 or IPv6 address and stores them in the 'ipv4_addrs' and
 * 'ipv6_addrs' fields of input param 'laddrs'.
 *
 * Return true if at least 'MAC' is found in 'address', false otherwise.
 *
 * The caller must call destroy_lport_addresses().
 */
bool
extract_lsp_addresses(char *address, struct lport_addresses *laddrs)
{
    init_lpa(laddrs);

    char *buf = address;
    int buf_index = 0;
    char *buf_end = buf + strlen(address);
    if (!ovs_scan_len(buf, &buf_index, ETH_ADDR_SCAN_FMT,
                      ETH_ADDR_SCAN_ARGS(laddrs->ea))) {
        laddrs->ea = eth_addr_zero;
        return false;
    }

    laddrs->ea_s = xasprintf(ETH_ADDR_FMT, ETH_ADDR_ARGS(laddrs->ea));

    ovs_be32 ip4;
    struct in6_addr ip6;
    unsigned int plen;
    char *error;

    /* Loop through the buffer and extract the IPv4/IPv6 addresses
     * and store in the 'laddrs'. Break the loop if invalid data is found.
     */
    buf += buf_index;
    while (buf < buf_end) {
        buf_index = 0;
        error = ip_parse_cidr_len(buf, &buf_index, &ip4, &plen);
        if (!error) {
            laddrs->n_ipv4_addrs++;
            laddrs->ipv4_addrs = xrealloc(laddrs->ipv4_addrs,
                sizeof (struct ipv4_netaddr) * laddrs->n_ipv4_addrs);

            struct ipv4_netaddr *na
                = &laddrs->ipv4_addrs[laddrs->n_ipv4_addrs - 1];
            set_ipv4_netaddr(ip4, plen, na);

            buf += buf_index;
            continue;
        }
        free(error);
        error = ipv6_parse_cidr_len(buf, &buf_index, &ip6, &plen);
        if (!error) {
            laddrs->n_ipv6_addrs++;
            laddrs->ipv6_addrs = xrealloc(
                laddrs->ipv6_addrs,
                sizeof(struct ipv6_netaddr) * laddrs->n_ipv6_addrs);

            struct ipv6_netaddr *na
                = &laddrs->ipv6_addrs[laddrs->n_ipv6_addrs - 1];
            set_ipv6_netaddr(ip6, plen, na);
        }

        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl, "invalid syntax '%s' in address", address);
            free(error);
            break;
        }
        buf += buf_index;
    }

    return true;
}

/* xxx Document this. */
bool
extract_lrp_networks(const struct nbrec_logical_router_port *lrp,
                     struct lport_addresses *lpa)
{
    init_lpa(lpa);

    if (!eth_addr_from_string(lrp->mac, &lpa->ea)) {
        lpa->ea = eth_addr_zero;
        return false;
    }
    lpa->ea_s = xasprintf(ETH_ADDR_FMT, ETH_ADDR_ARGS(lpa->ea));

    /* xxx We should be more consistent between lrp->networks and
     * lsp->addresses. */
    for (int i = 0; i < lrp->n_networks; i++) {
        ovs_be32 ip4;
        struct in6_addr ip6;
        unsigned int plen;
        char *error;

        error = ip_parse_cidr(lrp->networks[i], &ip4, &plen);
        if (!error) {
            if (!ip4 || plen == 32) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "bad 'networks' %s", lrp->networks[i]);
                continue;
            }

            lpa->n_ipv4_addrs++;
            lpa->ipv4_addrs = xrealloc(lpa->ipv4_addrs,
                sizeof (struct ipv4_netaddr) * lpa->n_ipv4_addrs);

            struct ipv4_netaddr *na = &lpa->ipv4_addrs[lpa->n_ipv4_addrs - 1];
            set_ipv4_netaddr(ip4, plen, na);

            continue;
        }
        free(error);

        error = ipv6_parse_cidr(lrp->networks[i], &ip6, &plen);
        if (!error) {
            /* xxx Check for invalid IPv6 addresses. */
            if (plen == 128) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "bad 'networks' %s", lrp->networks[i]);
                continue;
            }
            lpa->n_ipv6_addrs++;
            lpa->ipv6_addrs = xrealloc(lpa->ipv6_addrs,
                sizeof(struct ipv6_netaddr) * lpa->n_ipv6_addrs);

            struct ipv6_netaddr *na
                = &lpa->ipv6_addrs[lpa->n_ipv6_addrs - 1];
            set_ipv6_netaddr(ip6, plen, na);
        }

        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl, "invalid syntax '%s' in networks",
                         lrp->networks[i]);
            free(error);
        }
    }

    return true;
}

void
destroy_lport_addresses(struct lport_addresses *lpa)
{
    free(lpa->ea_s);

    for (int i = 0; i < lpa->n_ipv4_addrs; i++) {
        free(lpa->ipv4_addrs[i].addr_s);
        free(lpa->ipv4_addrs[i].network_s);
        free(lpa->ipv4_addrs[i].bcast_s);
    }
    free(lpa->ipv4_addrs);

    for (int i = 0; i < lpa->n_ipv6_addrs; i++) {
        free(lpa->ipv6_addrs[i].addr_s);
        free(lpa->ipv6_addrs[i].network_s);
    }
    free(lpa->ipv6_addrs);
}

/* Allocates a key for NAT conntrack zone allocation for a provided
 * 'port_binding' record and a 'type'.
 *
 * It is the caller's responsibility to free the allocated memory. */
char *
alloc_nat_zone_key(const struct sbrec_port_binding *port_binding,
                   const char *type)
{
    return xasprintf(UUID_FMT"_%s",
                     UUID_ARGS(&port_binding->datapath->header_.uuid), type);
}

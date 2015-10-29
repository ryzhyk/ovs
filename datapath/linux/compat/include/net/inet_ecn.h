#ifndef INET_ECN_WRAPPER_H
#define INET_ECN_WRAPPER_H

#include_next <net/inet_ecn.h>

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
/*
 * RFC 6080 4.2
 *  To decapsulate the inner header at the tunnel egress, a compliant
 *  tunnel egress MUST set the outgoing ECN field to the codepoint at the
 *  intersection of the appropriate arriving inner header (row) and outer
 *  header (column) in Figure 4
 *
 *      +---------+------------------------------------------------+
 *      |Arriving |            Arriving Outer Header               |
 *      |   Inner +---------+------------+------------+------------+
 *      |  Header | Not-ECT | ECT(0)     | ECT(1)     |     CE     |
 *      +---------+---------+------------+------------+------------+
 *      | Not-ECT | Not-ECT |Not-ECT(!!!)|Not-ECT(!!!)| <drop>(!!!)|
 *      |  ECT(0) |  ECT(0) | ECT(0)     | ECT(1)     |     CE     |
 *      |  ECT(1) |  ECT(1) | ECT(1) (!) | ECT(1)     |     CE     |
 *      |    CE   |      CE |     CE     |     CE(!!!)|     CE     |
 *      +---------+---------+------------+------------+------------+
 *
 *             Figure 4: New IP in IP Decapsulation Behaviour
 *
 *  returns 0 on success
 *          1 if something is broken and should be logged (!!! above)
 *          2 if packet should be dropped
 */
static inline int INET_ECN_decapsulate(struct sk_buff *skb,
				       __u8 outer, __u8 inner)
{
	if (INET_ECN_is_not_ect(inner)) {
		switch (outer & INET_ECN_MASK) {
		case INET_ECN_NOT_ECT:
			return 0;
		case INET_ECN_ECT_0:
		case INET_ECN_ECT_1:
			return 1;
		case INET_ECN_CE:
			return 2;
		}
	}

	if (INET_ECN_is_ce(outer))
		INET_ECN_set_ce(skb);

	return 0;
}

static inline int IP_ECN_decapsulate(const struct iphdr *oiph,
				     struct sk_buff *skb)
{
	__u8 inner;

	if (skb->protocol == htons(ETH_P_IP))
		inner = ip_hdr(skb)->tos;
	else if (skb->protocol == htons(ETH_P_IPV6))
		inner = ipv6_get_dsfield(ipv6_hdr(skb));
	else
		return 0;

	return INET_ECN_decapsulate(skb, oiph->tos, inner);
}

static inline int IP6_ECN_decapsulate(const struct ipv6hdr *oipv6h,
				      struct sk_buff *skb)
{
	__u8 inner;

	if (skb->protocol == htons(ETH_P_IP))
		inner = ip_hdr(skb)->tos;
	else if (skb->protocol == htons(ETH_P_IPV6))
		inner = ipv6_get_dsfield(ipv6_hdr(skb));
	else
		return 0;

	return INET_ECN_decapsulate(skb, ipv6_get_dsfield(oipv6h), inner);
}
#endif /* < 3.10 */
#endif /* INET_ECN_WRAPPER_H */

#define KBUILD_MODNAME "ratelimit"

#include <linux/bpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "ratelimit.h"

#define ratelimit_printk(fmt, ...)                                   \
    ({                                                               \
        char ____fmt[] = fmt;                                        \
        bpf_trace_printk (____fmt, sizeof (____fmt), ##__VA_ARGS__); \
    })

#define DEFAULT_DET_KEY_ENTRIES (100000 * 2)

struct
{
    __uint (type, BPF_MAP_TYPE_HASH);
    __uint (pinning, LIBBPF_PIN_BY_NAME); // ebpf实例数据共享
    __uint (max_entries, DEFAULT_DET_KEY_ENTRIES);
    __type (key, ratelimit_edt_key_t);
    __type (value, ratelimit_edt_value_t);
    __uint (map_flags, BPF_F_NO_PREALLOC);
} ratelimit_ip_edt SEC (".maps");

typedef struct
{
    ratelimit_ipaddr46_t src;
    ratelimit_ipaddr46_t dst;
    __u16 sport; // netbit
    __u16 dport; // netbit
    __u8 proto;
} ratelimit_tuple_t;

static int
ratelimit_ip_edt_sched (struct __sk_buff *skb, const ratelimit_tuple_t *tuple, const ratelimit_direction_t direction)
{
    __u64 now;
    __u64 Bps; // Bytes per second
    ratelimit_edt_key_t edt_key = { 0 };
    ratelimit_edt_value_t *edt_value = NULL;
    // 限速内网终端 DIRECTION_EGRESS：下行限速[目的IP] DIRECTION_INGRESS：上行限速[源IP]
    edt_key.ipaddr = (DIRECTION_EGRESS == direction) ? tuple->dst : tuple->src;
    edt_key.direction = direction;

    edt_value = bpf_map_lookup_elem (&ratelimit_ip_edt, &edt_key);
    if (!edt_value)
        return TC_ACT_OK; // 没有速率限制，直接发送
    if (!edt_value->bps)
        return TC_ACT_OK; // 没有速率限制，直接发送

    Bps = READ_ONCE (edt_value->bps) >> 3; // 转换为字节每秒
    if (!Bps)
        return TC_ACT_OK; // 没有速率限制，直接发送

    now = bpf_ktime_get_ns ();
    if (DIRECTION_EGRESS == direction) {
        __u64 delay, t, t_next;

        t = skb->tstamp;
        if (t < now)
            t = now;
        // 计算最早发送时间
        delay = ((__u64)(skb->wire_len)) * NSEC_PER_SEC / Bps;
        t_next = READ_ONCE (edt_value->t_last) + delay;
        if (t_next <= t) {
            WRITE_ONCE (edt_value->t_last, t);
            return TC_ACT_OK; // 第一个包，初始化最早发送时间，直接发送
        }
        /* FQ implements a drop horizon, see also 39d010504e6b ("net_sched:
         * sch_fq: add horizon attribute"). However, we explicitly need the
         * drop horizon here to i) avoid having t_last messed up and ii) to
         * potentially allow for per aggregate control.
         */
        if (t_next - now >= edt_value->t_horizon_drop)
            return TC_ACT_SHOT; // 当前报文未到发送时间，丢弃

        WRITE_ONCE (edt_value->t_last, t_next);
        skb->tstamp = t_next;
        //     /* TODO: Hack to avoid defaulting prio 0 when user doesn't specify anything.
        //  * Priority set by user will always be 1 greater than what scheduler expects.
        //  */
        //     if (edt_value->prio)
        //         ctx->priority = edt_value->prio - 1;
        return TC_ACT_OK;
    } else {
        int retcode = TC_ACT_OK;
        __u64 tokens, t_last, elapsed_time;

        t_last = READ_ONCE (edt_value->t_last);
        tokens = READ_ONCE (edt_value->tokens);
        elapsed_time = now - t_last;
        if (elapsed_time > 0) {
            tokens += (Bps * elapsed_time / NSEC_PER_SEC);
            if (tokens > Bps)
                tokens = Bps;
        }
        if (tokens >= skb->wire_len)
            tokens -= skb->wire_len;
        else
            retcode = TC_ACT_SHOT;

        WRITE_ONCE (edt_value->t_last, now);
        WRITE_ONCE (edt_value->tokens, tokens);

        return retcode;
    }
}

static int
parse_layer4 (struct __sk_buff *skb, ratelimit_tuple_t *tuple, void *l4, const ratelimit_direction_t direction)
{
    const void *data_end = (void *)(long)skb->data_end;

    switch (tuple->proto) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp0 = (struct tcphdr *)l4;
        if ((void *)(tcp0 + 1) > data_end)
            return TC_ACT_OK;

        tuple->sport = tcp0->source;
        tuple->dport = tcp0->dest;
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp0 = (struct udphdr *)l4;
        if ((void *)(udp0 + 1) > data_end)
            return TC_ACT_OK;

        tuple->sport = udp0->source;
        tuple->dport = udp0->dest;
    } break;
    default:
        break;
    }

    return TC_ACT_OK;
}

static int
dispatch_ipv4 (struct __sk_buff *skb, void *ip, const ratelimit_direction_t direction)
{
    int retcode = TC_ACT_OK;
    const void *data_end = (void *)(long)skb->data_end;
    __u16 l3offset;
    struct iphdr *ip0 = ip;
    ratelimit_tuple_t tuple = { 0 };

    // 丢弃异常报文
    if ((void *)(ip0 + 1) > data_end)
        return retcode;

    l3offset = ip0->ihl * 4;
    if ((void *)(((unsigned char *)ip) + l3offset) > data_end)
        return retcode;

    tuple.src.ip4.addr.s_addr = ip0->saddr;
    tuple.dst.ip4.addr.s_addr = ip0->daddr;
    tuple.proto = ip0->protocol;
    parse_layer4 (skb, &tuple, ((unsigned char *)ip) + l3offset, direction);

    return ratelimit_ip_edt_sched (skb, &tuple, direction);
}

static int
dispatch_ipv6 (struct __sk_buff *skb, void *ip, const ratelimit_direction_t direction)
{
    int retcode = TC_ACT_OK;
    const void *data_end = (void *)(long)skb->data_end;
    __u16 l3offset;
    struct ipv6hdr *ip0 = ip;
    ratelimit_tuple_t tuple = { 0 };

    // 丢弃异常报文
    if ((void *)(ip0 + 1) > data_end)
        return retcode;

    l3offset = sizeof (struct ipv6hdr);
    if ((void *)(((unsigned char *)ip) + l3offset) > data_end)
        return retcode;

    tuple.src.ip6.addr = ip0->saddr;
    tuple.dst.ip6.addr = ip0->daddr;
    tuple.proto = ip0->nexthdr;
    parse_layer4 (skb, &tuple, ((unsigned char *)ip) + l3offset, direction);

    return ratelimit_ip_edt_sched (skb, &tuple, direction);
}

static int
dispatch_tun (struct __sk_buff *skb, const ratelimit_direction_t direction)
{
    int retcode = TC_ACT_OK;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    const struct iphdr *ip0 = (struct iphdr *)data;

    if ((void *)(ip0 + 1) > data_end)
        return retcode;

    switch (ip0->version) {
    case 4:
        retcode = dispatch_ipv4 (skb, data, direction);
        break;
    case 6:
        retcode = dispatch_ipv6 (skb, data, direction);
        break;
    default:
#if RATELIMIT_DBG_ON
        ratelimit_printk ("[tun]unknown packet protocol[%d] direction[%d]\r\n", ip0->version, direction);
#endif
        break;
    }

    return retcode;
}

static int
dispatch_tap (struct __sk_buff *skb, const ratelimit_direction_t direction)
{
    int retcode = TC_ACT_OK;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    const struct ethhdr *eth0 = (struct ethhdr *)data;

    if ((void *)(eth0 + 1) > data_end)
        return retcode;

    switch (bpf_ntohs (eth0->h_proto)) {
    case ETH_P_IP:
        retcode = dispatch_ipv4 (skb, (void *)(eth0 + 1), direction);
        break;
    case ETH_P_IPV6:
        retcode = dispatch_ipv6 (skb, (void *)(eth0 + 1), direction);
        break;
    default:
#if RATELIMIT_DBG_ON
        ratelimit_printk ("[tap]unknown packet protocol[%d] direction[%d]\r\n", eth0->h_proto, direction);
#endif
        break;
    }

    return retcode;
}

SEC ("ratelimit/tun/egress")
int
ratelimit_tun_egress (struct __sk_buff *skb)
{
    return dispatch_tun (skb, DIRECTION_EGRESS);
}

SEC ("ratelimit/tun/ingress")
int
ratelimit_tun_ingress (struct __sk_buff *skb)
{
    return dispatch_tun (skb, DIRECTION_INGRESS);
}

SEC ("ratelimit/tap/egress")
int
ratelimit_tap_egress (struct __sk_buff *skb)
{
    return dispatch_tap (skb, DIRECTION_EGRESS);
}

SEC ("ratelimit/tap/ingress")
int
ratelimit_tap_ingress (struct __sk_buff *skb)
{
    return dispatch_tap (skb, DIRECTION_INGRESS);
}

char _license[] SEC ("license") = "GPL";
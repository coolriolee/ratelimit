#ifndef __EBPF_RATELIMIT_H__
#define __EBPF_RATELIMIT_H__

#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>

#define RATELIMIT_DBG_ON 1
#define RATELIMIT_DBG_ON4 0
#define RATELIMIT_DBG_ON6 0

// IPv4
typedef union
{
    struct in_addr addr;
    __u8 addr_u8[4];
} ratelimit_ipaddr4_t; // netbit

// IPv6
typedef struct
{
    struct in6_addr addr;
} ratelimit_ipaddr6_t; // netbit

typedef union
{
    ratelimit_ipaddr4_t ip4;
    ratelimit_ipaddr6_t ip6;
} ratelimit_ipaddr46_t;

// 定义报文流向
typedef enum
{
    // TX
    DIRECTION_EGRESS = 0,
    // RX
    DIRECTION_INGRESS = 1,
} ratelimit_direction_t;

typedef struct
{
    ratelimit_ipaddr46_t ipaddr;
    ratelimit_direction_t direction;
} ratelimit_edt_key_t;

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC (1000ULL * 1000ULL * 1000UL)
#endif /* NSEC_PER_SEC */
#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC (1000ULL * 1000ULL)
#endif /* NSEC_PER_MSEC */
#ifndef NSEC_PER_USEC
#define NSEC_PER_USEC (1000UL)
#endif /* NSEC_PER_USEC */

typedef struct
{
    __u64 bps; // Received bits per second
    __u64 t_last;
    union
    {
        __u64 t_horizon_drop;
        __u64 tokens;
    };
} ratelimit_edt_value_t;

#endif
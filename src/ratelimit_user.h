#ifndef __RATELIMIT_USER_H__
#define __RATELIMIT_USER_H__

#include <linux/types.h>

#include "ratelimit.h"

extern int ratelimit_fini ();
extern int ratelimit_add_limitinfo (const ratelimit_ipaddr46_t ipaddr, const __u64 rxbps, const __u64 txbps);
extern int ratelimit_del_limitinfo (const ratelimit_ipaddr46_t ipaddr);
extern int ratelimit_show_limitinfo (const ratelimit_ipaddr46_t ipaddr);

#endif /* __RATELIMIT_USER_H__ */
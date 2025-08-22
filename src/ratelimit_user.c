#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <assert.h>

#include "ratelimit_user.h"

static int mapfd_ratelimit_ip_edt = -1;
#define DEFAULT_PATH "/sys/fs/bpf/tc/globals"
#define DEFAULT_RATELIMIT_EDT_PATH DEFAULT_PATH "/ratelimit_ip_edt"

static int
ratelimit_init ()
{
    if (mapfd_ratelimit_ip_edt == -1)
        mapfd_ratelimit_ip_edt = bpf_obj_get (DEFAULT_RATELIMIT_EDT_PATH);
    if (mapfd_ratelimit_ip_edt < 0)
        return -1;

    return 0;
}

int
ratelimit_fini ()
{
    if (mapfd_ratelimit_ip_edt > 0)
        close (mapfd_ratelimit_ip_edt);
    mapfd_ratelimit_ip_edt = -1;

    return 0;
}

int
ratelimit_add_limitinfo (const ratelimit_ipaddr46_t ipaddr, const __u64 rxbps, const __u64 txbps)
{
    ratelimit_edt_key_t edt_key = { 0 };
    ratelimit_edt_value_t edt_value = { 0 };

    if (ratelimit_init () < 0) {
        fprintf (stderr, "Failed to initialize ratelimit tools\n");
        return -1;
    }

    edt_key.ipaddr = ipaddr;
    // 终端限速，下行[rxbps]
    edt_key.direction = DIRECTION_EGRESS;
    edt_value.bps = rxbps;
    edt_value.t_horizon_drop = 2 * NSEC_PER_SEC;
    if (bpf_map_update_elem (mapfd_ratelimit_ip_edt, &edt_key, &edt_value, BPF_ANY) < 0) {
        fprintf (stderr, "Failed to update ratelimit info[EGRESS].\n");
        return -1;
    }

    // 终端限速，上行[txbps]
    edt_key.direction = DIRECTION_INGRESS;
    edt_value.bps = txbps;
    edt_value.tokens = 0;
    if (bpf_map_update_elem (mapfd_ratelimit_ip_edt, &edt_key, &edt_value, BPF_ANY) < 0) {
        fprintf (stderr, "Failed to update ratelimit info[INGRESS].\n");
        return -1;
    }

    return 0;
}

int
ratelimit_del_limitinfo (const ratelimit_ipaddr46_t ipaddr)
{
    ratelimit_edt_key_t edt_key = { 0 };

    if (ratelimit_init () < 0) {
        fprintf (stderr, "Failed to initialize ratelimit tools\n");
        return -1;
    }

    edt_key.ipaddr = ipaddr;
    // 终端限速，下行[rxbps]
    edt_key.direction = DIRECTION_EGRESS;
    if (bpf_map_delete_elem (mapfd_ratelimit_ip_edt, &edt_key) < 0) {
        fprintf (stderr, "Failed to delete ratelimit info[EGRESS].\n");
        return -1;
    }

    // 终端限速，上行[txbps]
    edt_key.direction = DIRECTION_INGRESS;
    if (bpf_map_delete_elem (mapfd_ratelimit_ip_edt, &edt_key) < 0) {
        fprintf (stderr, "Failed to delete ratelimit info[INGRESS].\n");
        return -1;
    }

    return 0;
}

int
ratelimit_show_limitinfo (const ratelimit_ipaddr46_t ipaddr)
{
    ratelimit_edt_key_t edt_key = { 0 };
    ratelimit_edt_value_t edt_value = { 0 };

    if (ratelimit_init () < 0) {
        fprintf (stderr, "Failed to initialize ratelimit tools\n");
        return -1;
    }

    edt_key.ipaddr = ipaddr;
    // 终端限速，下行[rxbps]
    edt_key.direction = DIRECTION_EGRESS;
    if (bpf_map_lookup_elem (mapfd_ratelimit_ip_edt, &edt_key, &edt_value) < 0) {
        fprintf (stderr, "Failed to lookup ratelimit info[EGRESS].\n");
        return -1;
    }
    fprintf (stdout, "下行限速：%llu\r\n", edt_value.bps);

    // 终端限速，上行[txbps]
    edt_key.direction = DIRECTION_INGRESS;
    if (bpf_map_lookup_elem (mapfd_ratelimit_ip_edt, &edt_key, &edt_value) < 0) {
        fprintf (stderr, "Failed to lookup ratelimit info[INGRESS].\n");
        return -1;
    }
    fprintf (stdout, "上行限速：%llu\r\n", edt_value.bps);

    return 0;
}
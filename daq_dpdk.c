/**
 *
 *
 *
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wunused-but-set-parameter"
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wreturn-type"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>

/* DAQ lib */
#include <daq_api.h>
#include <sfbpf.h>
#include <odp.h>
#include <daq.h>
#include <daq_common.h>
#include <odp.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

#define DAQ_DPDK_VERSION 1
#define DAQ_DPDK_MAX_NUM_DEVICES 16
#define DAQ_DPDK_PASSIVE_DEV_IDX 0
#define DAQ_DPDK_STAT 1000000

/*
 * header main
 */

/* Logical cores */
#define kAPPMAXSOCKET 2

#ifndef APP_MAX_LCORES
#define APP_MAX_LCORES       RTE_MAX_LCORE
#endif

#ifndef APP_MAX_NIC_PORTS
#define APP_MAX_NIC_PORTS    32 //RTE_MAX_ETHPORTS
#endif

#ifndef APP_MAX_RX_QUEUES_PER_NIC_PORT
#define APP_MAX_RX_QUEUES_PER_NIC_PORT 128
#endif

#ifndef APP_MAX_TX_QUEUES_PER_NIC_PORT
#define APP_MAX_TX_QUEUES_PER_NIC_PORT 128
#endif

#ifndef APP_MAX_IO_LCORES
#define APP_MAX_IO_LCORES 16
#endif

//#if (APP_MAX_IO_LCORES > APP_MAX_LCORES)
//#error "APP_MAX_IO_LCORES is too big"
//#endif

#ifndef APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE
#define APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE 16
#endif

#ifndef APP_MAX_NIC_TX_PORTS_PER_IO_LCORE
#define APP_MAX_NIC_TX_PORTS_PER_IO_LCORE 16
#endif
//#if (APP_MAX_NIC_TX_PORTS_PER_IO_LCORE > APP_MAX_NIC_PORTS)
//#error "APP_MAX_NIC_TX_PORTS_PER_IO_LCORE too big"
//#endif

#ifndef APP_MAX_WORKER_LCORES
#define APP_MAX_WORKER_LCORES 16
#endif
//#if (APP_MAX_WORKER_LCORES > APP_MAX_LCORES)
//#error "APP_MAX_WORKER_LCORES is too big"
//#endif


/* Mempools */
#ifndef APP_DEFAULT_MBUF_DATA_SIZE
#define APP_DEFAULT_MBUF_DATA_SIZE  RTE_MBUF_DEFAULT_BUF_SIZE
#endif

#ifndef APP_DEFAULT_MEMPOOL_BUFFERS
#define APP_DEFAULT_MEMPOOL_BUFFERS   8192 * 4
#endif

#ifndef APP_DEFAULT_MEMPOOL_CACHE_SIZE
#define APP_DEFAULT_MEMPOOL_CACHE_SIZE  256
#endif

/* LPM Tables */
#ifndef APP_MAX_LPM_RULES
#define APP_MAX_LPM_RULES 1024
#endif

/* NIC RX */
#ifndef APP_DEFAULT_NIC_RX_RING_SIZE
#define APP_DEFAULT_NIC_RX_RING_SIZE 1024
#endif

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#ifndef APP_DEFAULT_NIC_RX_PTHRESH
#define APP_DEFAULT_NIC_RX_PTHRESH  8
#endif

#ifndef APP_DEFAULT_NIC_RX_HTHRESH
#define APP_DEFAULT_NIC_RX_HTHRESH  8
#endif

#ifndef APP_DEFAULT_NIC_RX_WTHRESH
#define APP_DEFAULT_NIC_RX_WTHRESH  4
#endif

#ifndef APP_DEFAULT_NIC_RX_FREE_THRESH
#define APP_DEFAULT_NIC_RX_FREE_THRESH  64
#endif

#ifndef APP_DEFAULT_NIC_RX_DROP_EN
#define APP_DEFAULT_NIC_RX_DROP_EN 0
#endif

/* NIC TX */
#ifndef APP_DEFAULT_NIC_TX_RING_SIZE
#define APP_DEFAULT_NIC_TX_RING_SIZE 1024
#endif

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#ifndef APP_DEFAULT_NIC_TX_PTHRESH
#define APP_DEFAULT_NIC_TX_PTHRESH  36
#endif

#ifndef APP_DEFAULT_NIC_TX_HTHRESH
#define APP_DEFAULT_NIC_TX_HTHRESH  0
#endif

#ifndef APP_DEFAULT_NIC_TX_WTHRESH
#define APP_DEFAULT_NIC_TX_WTHRESH  0
#endif

#ifndef APP_DEFAULT_NIC_TX_FREE_THRESH
#define APP_DEFAULT_NIC_TX_FREE_THRESH  0
#endif

#ifndef APP_DEFAULT_NIC_TX_RS_THRESH
#define APP_DEFAULT_NIC_TX_RS_THRESH  0
#endif

/* Software Rings */
#ifndef APP_DEFAULT_RING_RX_SIZE
#define APP_DEFAULT_RING_RX_SIZE 1024
#endif

#ifndef APP_DEFAULT_RING_TX_SIZE
#define APP_DEFAULT_RING_TX_SIZE 1024
#endif

/* Bursts */
#ifndef APP_MBUF_ARRAY_SIZE
#define APP_MBUF_ARRAY_SIZE   512
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_RX_READ
#define APP_DEFAULT_BURST_SIZE_IO_RX_READ  144
#endif

//#if (APP_DEFAULT_BURST_SIZE_IO_RX_READ > APP_MBUF_ARRAY_SIZE)
//#error "APP_DEFAULT_BURST_SIZE_IO_RX_READ is too big"
//#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_RX_WRITE
#define APP_DEFAULT_BURST_SIZE_IO_RX_WRITE  144
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_RX_WRITE > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_RX_WRITE is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_TX_READ
#define APP_DEFAULT_BURST_SIZE_IO_TX_READ  144
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_TX_READ > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_TX_READ is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_TX_WRITE
#define APP_DEFAULT_BURST_SIZE_IO_TX_WRITE  144
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_TX_WRITE > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_TX_WRITE is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_WORKER_READ
#define APP_DEFAULT_BURST_SIZE_WORKER_READ  144
#endif
#if ((2 * APP_DEFAULT_BURST_SIZE_WORKER_READ) > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_WORKER_READ is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_WORKER_WRITE
#define APP_DEFAULT_BURST_SIZE_WORKER_WRITE  144
#endif
#if (APP_DEFAULT_BURST_SIZE_WORKER_WRITE > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_WORKER_WRITE is too big"
#endif

/* Load balancing logic */
#ifndef APP_DEFAULT_IO_RX_LB_POS
#define APP_DEFAULT_IO_RX_LB_POS 29
#endif
#if (APP_DEFAULT_IO_RX_LB_POS >= 64)
#error "APP_DEFAULT_IO_RX_LB_POS is too big"
#endif

struct app_mbuf_array {
    struct rte_mbuf *array[APP_MBUF_ARRAY_SIZE];
    uint32_t n_mbufs;
};

enum app_lcore_type {
    e_APP_LCORE_DISABLED = 0,
    e_APP_LCORE_IO,
    e_APP_LCORE_WORKER
};

struct app_lcore_params_io {
    /* I/O RX */
    struct {
        /* NIC */
        struct {
            uint8_t port;
            uint8_t queue;
        } nic_queues[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
        uint32_t n_nic_queues;

        /* Rings */
        struct rte_ring *rings[APP_MAX_WORKER_LCORES];
        uint32_t n_rings;

        /* Internal buffers */
        struct app_mbuf_array mbuf_in;
        struct app_mbuf_array mbuf_out[APP_MAX_WORKER_LCORES];
        uint8_t mbuf_out_flush[APP_MAX_WORKER_LCORES];

        /* Stats */
        uint32_t nic_queues_count[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
        uint32_t nic_queues_iters[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
        uint32_t rings_count[APP_MAX_WORKER_LCORES];
        uint32_t rings_iters[APP_MAX_WORKER_LCORES];
    } rx;

    /* I/O TX */
    struct {
        /* Rings */
        struct rte_ring *rings[APP_MAX_NIC_PORTS][APP_MAX_WORKER_LCORES];

        /* NIC */
        uint8_t nic_ports[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
        uint32_t n_nic_ports;

        /* Internal buffers */
        struct app_mbuf_array mbuf_out[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
        uint8_t mbuf_out_flush[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];

        /* Stats */
        uint32_t rings_count[APP_MAX_NIC_PORTS][APP_MAX_WORKER_LCORES];
        uint32_t rings_iters[APP_MAX_NIC_PORTS][APP_MAX_WORKER_LCORES];
        uint32_t nic_ports_count[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
        uint32_t nic_ports_iters[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
    } tx;
};

struct app_lcore_params_worker {
    /* Rings */
    struct rte_ring *rings_in[APP_MAX_IO_LCORES];
    uint32_t n_rings_in;
    struct rte_ring *rings_out[APP_MAX_NIC_PORTS];

    /* LPM table */
    struct rte_lpm *lpm_table;
    uint32_t worker_id;


    /* Internal buffers */
    struct app_mbuf_array mbuf_in;
    struct app_mbuf_array mbuf_out[APP_MAX_NIC_PORTS];
    uint8_t mbuf_out_flush[APP_MAX_NIC_PORTS];

    /* Stats */
    uint32_t rings_in_count[APP_MAX_IO_LCORES];
    uint32_t rings_in_iters[APP_MAX_IO_LCORES];
    uint32_t rings_out_count[APP_MAX_NIC_PORTS];
    uint32_t rings_out_iters[APP_MAX_NIC_PORTS];
};

struct app_lcore_params {
    union {
        struct app_lcore_params_io io;
        struct app_lcore_params_worker worker;
    };
    enum app_lcore_type type;
    struct rte_mempool *pool;
};

struct app_lpm_rule {
    uint32_t ip;
    uint8_t depth;
    uint8_t if_out;
};

typedef struct app_params {
    /* lcore */
    struct app_lcore_params lcore_params[APP_MAX_LCORES];

    /* NIC */
    uint8_t nic_rx_queue_mask[APP_MAX_NIC_PORTS][APP_MAX_RX_QUEUES_PER_NIC_PORT];
    uint8_t nic_tx_port_mask[APP_MAX_NIC_PORTS];

    /* mbuf pools */
    struct rte_mempool *pools[kAPPMAXSOCKET];

    /* LPM tables */
    struct rte_lpm *lpm_tables[kAPPMAXSOCKET];
    struct app_lpm_rule lpm_rules[APP_MAX_LPM_RULES];
    uint32_t n_lpm_rules;

    /* rings */
    uint32_t nic_rx_ring_size;
    uint32_t nic_tx_ring_size;
    uint32_t ring_rx_size;
    uint32_t ring_tx_size;

    /* burst size */
    uint32_t burst_size_io_rx_read;
    uint32_t burst_size_io_rx_write;
    uint32_t burst_size_io_tx_read;
    uint32_t burst_size_io_tx_write;
    uint32_t burst_size_worker_read;
    uint32_t burst_size_worker_write;

    /* load balancing opts */
    uint8_t pos_lb;

    /* DAQ opts */
    int cntPkt;
} app;

//struct app_params app;
int app_parse_args(struct app_params app, int argc, char **argv);
void app_print_usage(struct app_params app);
void app_init(struct app_params app);
int dpdk_daq_main_loop(struct app_params app);
int app_get_nic_rx_queues_per_port(struct app_params app, uint8_t port);
int app_get_lcore_for_nic_rx(struct app_params app, uint8_t port, uint8_t queue, uint32_t *lcore_out);
int app_get_lcore_for_nic_tx(struct app_params app, uint8_t port, uint32_t *lcore_out);
int app_is_socket_used(struct app_params app, uint32_t socket);
uint32_t app_get_lcores_io_rx(struct app_params app);
uint32_t app_get_lcores_worker(struct app_params app);
void app_print_params(struct app_params app);

/* 
 * Configuration
 */
static const char usage[] =
"                                                                               \n"
"    dpdk-daq  <EAL PARAMS> -- <APP PARAMS>                                     \n"
"                                                                               \n"
"Application manadatory parameters:                                             \n"
"    --rx \"(PORT, QUEUE, LCORE), ...\" : List of NIC RX ports and queues       \n"
"           handled by the I/O RX lcores                                        \n"
"    --tx \"(PORT, LCORE), ...\" : List of NIC TX ports handled by the I/O TX   \n"
"           lcores                                                              \n"
"    --w \"LCORE, ...\" : List of the worker lcores                             \n"
"    --lpm \"IP / PREFIX => PORT; ...\" : List of LPM rules used by the worker  \n"
"           lcores for packet forwarding                                        \n"
"                                                                               \n"
"Application optional parameters:                                               \n"
"    --rsz \"A, B, C, D\" : Ring sizes                                          \n"
"           A = Size (in number of buffer descriptors) of each of the NIC RX    \n"
"               rings read by the I/O RX lcores (default value is %u)           \n"
"           B = Size (in number of elements) of each of the SW rings used by the\n"
"               I/O RX lcores to send packets to worker lcores (default value is\n"
"               %u)                                                             \n"
"           C = Size (in number of elements) of each of the SW rings used by the\n"
"               worker lcores to send packets to I/O TX lcores (default value is\n"
"               %u)                                                             \n"
"           D = Size (in number of buffer descriptors) of each of the NIC TX    \n"
"               rings written by I/O TX lcores (default value is %u)            \n"
"    --bsz \"(A, B), (C, D), (E, F)\" :  Burst sizes                            \n"
"           A = I/O RX lcore read burst size from NIC RX (default value is %u)  \n"
"           B = I/O RX lcore write burst size to output SW rings (default value \n"
"               is %u)                                                          \n"
"           C = Worker lcore read burst size from input SW rings (default value \n"
"               is %u)                                                          \n"
"           D = Worker lcore write burst size to output SW rings (default value \n"
"               is %u)                                                          \n"
"           E = I/O TX lcore read burst size from input SW rings (default value \n"
"               is %u)                                                          \n"
"           F = I/O TX lcore write burst size to NIC TX (default value is %u)   \n"
"    --pos-lb POS : Position of the 1-byte field within the input packet used by\n"
"           the I/O RX lcores to identify the worker lcore for the current      \n"
"           packet (default value is %u)                                        \n";

void
app_print_usage(struct app_params app)
{
	printf(usage,
		APP_DEFAULT_NIC_RX_RING_SIZE,
		APP_DEFAULT_RING_RX_SIZE,
		APP_DEFAULT_RING_TX_SIZE,
		APP_DEFAULT_NIC_TX_RING_SIZE,
		APP_DEFAULT_BURST_SIZE_IO_RX_READ,
		APP_DEFAULT_BURST_SIZE_IO_RX_WRITE,
		APP_DEFAULT_BURST_SIZE_WORKER_READ,
		APP_DEFAULT_BURST_SIZE_WORKER_WRITE,
		APP_DEFAULT_BURST_SIZE_IO_TX_READ,
		APP_DEFAULT_BURST_SIZE_IO_TX_WRITE,
		APP_DEFAULT_IO_RX_LB_POS
	);
}

#ifndef APP_ARG_RX_MAX_CHARS
#define APP_ARG_RX_MAX_CHARS     4096
#endif

#ifndef APP_ARG_RX_MAX_TUPLES
#define APP_ARG_RX_MAX_TUPLES    128
#endif

static int
str_to_unsigned_array(
	const char *s, size_t sbuflen,
	char separator,
	unsigned num_vals,
	unsigned *vals)
{
	char str[sbuflen+1];
	char *splits[num_vals];
	char *endptr = NULL;
	int i, num_splits = 0;

	/* copy s so we don't modify original string */
	snprintf(str, sizeof(str), "%s", s);
	num_splits = rte_strsplit(str, sizeof(str), splits, num_vals, separator);

	errno = 0;
	for (i = 0; i < num_splits; i++) {
		vals[i] = strtoul(splits[i], &endptr, 0);
		if (errno != 0 || *endptr != '\0')
			return -1;
	}

	return num_splits;
}

static int
str_to_unsigned_vals(
	const char *s,
	size_t sbuflen,
	char separator,
	unsigned num_vals, ...)
{
	unsigned i, vals[num_vals];
	va_list ap;

	num_vals = str_to_unsigned_array(s, sbuflen, separator, num_vals, vals);

	va_start(ap, num_vals);
	for (i = 0; i < num_vals; i++) {
		unsigned *u = va_arg(ap, unsigned *);
		*u = vals[i];
	}
	va_end(ap);
	return num_vals;
}

static int
parse_arg_rx(struct app_params app, const char *arg)
{
	const char *p0 = arg, *p = arg;
	uint32_t n_tuples;

	if (strnlen(arg, APP_ARG_RX_MAX_CHARS + 1) == APP_ARG_RX_MAX_CHARS + 1) {
		return -1;
	}

	n_tuples = 0;
	while ((p = strchr(p0,'(')) != NULL) {
		struct app_lcore_params *lp;
		uint32_t port, queue, lcore, i;

		p0 = strchr(p++, ')');
		if ((p0 == NULL) ||
		    (str_to_unsigned_vals(p, p0 - p, ',', 3, &port, &queue, &lcore) !=  3)) {
			return -2;
		}

		/* Enable port and queue for later initialization */
		if ((port >= APP_MAX_NIC_PORTS) || (queue >= APP_MAX_RX_QUEUES_PER_NIC_PORT)) {
			return -3;
		}
		if (app.nic_rx_queue_mask[port][queue] != 0) {
			return -4;
		}
		app.nic_rx_queue_mask[port][queue] = 1;

		/* Check and assign (port, queue) to I/O lcore */
		if (rte_lcore_is_enabled(lcore) == 0) {
			return -5;
		}

		if (lcore >= APP_MAX_LCORES) {
			return -6;
		}
		lp = &app.lcore_params[lcore];
		if (lp->type == e_APP_LCORE_WORKER) {
			return -7;
		}
		lp->type = e_APP_LCORE_IO;
		const size_t n_queues = RTE_MIN(lp->io.rx.n_nic_queues,
		                                RTE_DIM(lp->io.rx.nic_queues));
		for (i = 0; i < n_queues; i ++) {
			if ((lp->io.rx.nic_queues[i].port == port) &&
			    (lp->io.rx.nic_queues[i].queue == queue)) {
				return -8;
			}
		}
		if (lp->io.rx.n_nic_queues >= APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE) {
			return -9;
		}
		lp->io.rx.nic_queues[lp->io.rx.n_nic_queues].port = (uint8_t) port;
		lp->io.rx.nic_queues[lp->io.rx.n_nic_queues].queue = (uint8_t) queue;
		lp->io.rx.n_nic_queues ++;

		n_tuples ++;
		if (n_tuples > APP_ARG_RX_MAX_TUPLES) {
			return -10;
		}
	}

	if (n_tuples == 0) {
		return -11;
	}

	return 0;
}

#ifndef APP_ARG_TX_MAX_CHARS
#define APP_ARG_TX_MAX_CHARS     4096
#endif

#ifndef APP_ARG_TX_MAX_TUPLES
#define APP_ARG_TX_MAX_TUPLES    128
#endif

static int
parse_arg_tx(struct app_params app, const char *arg)
{
	const char *p0 = arg, *p = arg;
	uint32_t n_tuples;

	if (strnlen(arg, APP_ARG_TX_MAX_CHARS + 1) == APP_ARG_TX_MAX_CHARS + 1) {
		return -1;
	}

	n_tuples = 0;
	while ((p = strchr(p0,'(')) != NULL) {
		struct app_lcore_params *lp;
		uint32_t port, lcore, i;

		p0 = strchr(p++, ')');
		if ((p0 == NULL) ||
		    (str_to_unsigned_vals(p, p0 - p, ',', 2, &port, &lcore) !=  2)) {
			return -2;
		}

		/* Enable port and queue for later initialization */
		if (port >= APP_MAX_NIC_PORTS) {
			return -3;
		}
		if (app.nic_tx_port_mask[port] != 0) {
			return -4;
		}
		app.nic_tx_port_mask[port] = 1;

		/* Check and assign (port, queue) to I/O lcore */
		if (rte_lcore_is_enabled(lcore) == 0) {
			return -5;
		}

		if (lcore >= APP_MAX_LCORES) {
			return -6;
		}
		lp = &app.lcore_params[lcore];
		if (lp->type == e_APP_LCORE_WORKER) {
			return -7;
		}
		lp->type = e_APP_LCORE_IO;
		const size_t n_ports = RTE_MIN(lp->io.tx.n_nic_ports,
		                               RTE_DIM(lp->io.tx.nic_ports));
		for (i = 0; i < n_ports; i ++) {
			if (lp->io.tx.nic_ports[i] == port) {
				return -8;
			}
		}
		if (lp->io.tx.n_nic_ports >= APP_MAX_NIC_TX_PORTS_PER_IO_LCORE) {
			return -9;
		}
		lp->io.tx.nic_ports[lp->io.tx.n_nic_ports] = (uint8_t) port;
		lp->io.tx.n_nic_ports ++;

		n_tuples ++;
		if (n_tuples > APP_ARG_TX_MAX_TUPLES) {
			return -10;
		}
	}

	if (n_tuples == 0) {
		return -11;
	}

	return 0;
}

#ifndef APP_ARG_W_MAX_CHARS
#define APP_ARG_W_MAX_CHARS     4096
#endif

#ifndef APP_ARG_W_MAX_TUPLES
#define APP_ARG_W_MAX_TUPLES    APP_MAX_WORKER_LCORES
#endif

static int
parse_arg_w(struct app_params app, const char *arg)
{
	const char *p = arg;
	uint32_t n_tuples;

	if (strnlen(arg, APP_ARG_W_MAX_CHARS + 1) == APP_ARG_W_MAX_CHARS + 1) {
		return -1;
	}

	n_tuples = 0;
	while (*p != 0) {
		struct app_lcore_params *lp;
		uint32_t lcore;

		errno = 0;
		lcore = strtoul(p, NULL, 0);
		if ((errno != 0)) {
			return -2;
		}

		/* Check and enable worker lcore */
		if (rte_lcore_is_enabled(lcore) == 0) {
			return -3;
		}

		if (lcore >= APP_MAX_LCORES) {
			return -4;
		}
		lp = &app.lcore_params[lcore];
		if (lp->type == e_APP_LCORE_IO) {
			return -5;
		}
		lp->type = e_APP_LCORE_WORKER;

		n_tuples ++;
		if (n_tuples > APP_ARG_W_MAX_TUPLES) {
			return -6;
		}

		p = strchr(p, ',');
		if (p == NULL) {
			break;
		}
		p ++;
	}

	if (n_tuples == 0) {
		return -7;
	}

	if ((n_tuples & (n_tuples - 1)) != 0) {
		return -8;
	}

	return 0;
}

#ifndef APP_ARG_LPM_MAX_CHARS
#define APP_ARG_LPM_MAX_CHARS     4096
#endif

static int
parse_arg_lpm(struct app_params app, const char *arg)
{
	const char *p = arg, *p0;

	if (strnlen(arg, APP_ARG_LPM_MAX_CHARS + 1) == APP_ARG_TX_MAX_CHARS + 1) {
		return -1;
	}

	while (*p != 0) {
		uint32_t ip_a, ip_b, ip_c, ip_d, ip, depth, if_out;
		char *endptr;

		p0 = strchr(p, '/');
		if ((p0 == NULL) ||
		    (str_to_unsigned_vals(p, p0 - p, '.', 4, &ip_a, &ip_b, &ip_c, &ip_d) != 4)) {
			return -2;
		}

		p = p0 + 1;
		errno = 0;
		depth = strtoul(p, &endptr, 0);
		if (errno != 0 || *endptr != '=') {
			return -3;
		}
		p = strchr(p, '>');
		if (p == NULL) {
			return -4;
		}
		if_out = strtoul(++p, &endptr, 0);
		if (errno != 0 || (*endptr != '\0' && *endptr != ';')) {
			return -5;
		}

		if ((ip_a >= 256) || (ip_b >= 256) || (ip_c >= 256) || (ip_d >= 256) ||
		     (depth == 0) || (depth >= 32) ||
			 (if_out >= APP_MAX_NIC_PORTS)) {
			return -6;
		}
		ip = (ip_a << 24) | (ip_b << 16) | (ip_c << 8) | ip_d;

		if (app.n_lpm_rules >= APP_MAX_LPM_RULES) {
			return -7;
		}
		app.lpm_rules[app.n_lpm_rules].ip = ip;
		app.lpm_rules[app.n_lpm_rules].depth = (uint8_t) depth;
		app.lpm_rules[app.n_lpm_rules].if_out = (uint8_t) if_out;
		app.n_lpm_rules ++;

		p = strchr(p, ';');
		if (p == NULL) {
			return -8;
		}
		p ++;
	}

	if (app.n_lpm_rules == 0) {
		return -9;
	}

	return 0;
}

static int
app_check_lpm_table(struct app_params app)
{
	uint32_t rule;

	/* For each rule, check that the output I/F is enabled */
	for (rule = 0; rule < app.n_lpm_rules; rule ++)
	{
		uint32_t port = app.lpm_rules[rule].if_out;

		if (app.nic_tx_port_mask[port] == 0) {
			return -1;
		}
	}

	return 0;
}

static int
app_check_every_rx_port_is_tx_enabled(struct app_params app)
{
	uint8_t port;

	for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
		if ((app_get_nic_rx_queues_per_port(app, port) > 0) && (app.nic_tx_port_mask[port] == 0)) {
			return -1;
		}
	}

	return 0;
}

#ifndef APP_ARG_RSZ_CHARS
#define APP_ARG_RSZ_CHARS 63
#endif

static int
parse_arg_rsz(struct app_params app, const char *arg)
{
	if (strnlen(arg, APP_ARG_RSZ_CHARS + 1) == APP_ARG_RSZ_CHARS + 1) {
		return -1;
	}

	if (str_to_unsigned_vals(arg, APP_ARG_RSZ_CHARS, ',', 4,
			&app.nic_rx_ring_size,
			&app.ring_rx_size,
			&app.ring_tx_size,
			&app.nic_tx_ring_size) !=  4)
		return -2;


	if ((app.nic_rx_ring_size == 0) ||
		(app.nic_tx_ring_size == 0) ||
		(app.ring_rx_size == 0) ||
		(app.ring_tx_size == 0)) {
		return -3;
	}

	return 0;
}

#ifndef APP_ARG_BSZ_CHARS
#define APP_ARG_BSZ_CHARS 63
#endif

static int
parse_arg_bsz(struct app_params app, const char *arg)
{
	const char *p = arg, *p0;
	if (strnlen(arg, APP_ARG_BSZ_CHARS + 1) == APP_ARG_BSZ_CHARS + 1) {
		return -1;
	}

	p0 = strchr(p++, ')');
	if ((p0 == NULL) ||
	    (str_to_unsigned_vals(p, p0 - p, ',', 2, &app.burst_size_io_rx_read, &app.burst_size_io_rx_write) !=  2)) {
		return -2;
	}

	p = strchr(p0, '(');
	if (p == NULL) {
		return -3;
	}

	p0 = strchr(p++, ')');
	if ((p0 == NULL) ||
	    (str_to_unsigned_vals(p, p0 - p, ',', 2, &app.burst_size_worker_read, &app.burst_size_worker_write) !=  2)) {
		return -4;
	}

	p = strchr(p0, '(');
	if (p == NULL) {
		return -5;
	}

	p0 = strchr(p++, ')');
	if ((p0 == NULL) ||
	    (str_to_unsigned_vals(p, p0 - p, ',', 2, &app.burst_size_io_tx_read, &app.burst_size_io_tx_write) !=  2)) {
		return -6;
	}

	if ((app.burst_size_io_rx_read == 0) ||
		(app.burst_size_io_rx_write == 0) ||
		(app.burst_size_worker_read == 0) ||
		(app.burst_size_worker_write == 0) ||
		(app.burst_size_io_tx_read == 0) ||
		(app.burst_size_io_tx_write == 0)) {
		return -7;
	}

	if ((app.burst_size_io_rx_read > APP_MBUF_ARRAY_SIZE) ||
		(app.burst_size_io_rx_write > APP_MBUF_ARRAY_SIZE) ||
		(app.burst_size_worker_read > APP_MBUF_ARRAY_SIZE) ||
		(app.burst_size_worker_write > APP_MBUF_ARRAY_SIZE) ||
		((2 * app.burst_size_io_tx_read) > APP_MBUF_ARRAY_SIZE) ||
		(app.burst_size_io_tx_write > APP_MBUF_ARRAY_SIZE)) {
		return -8;
	}

	return 0;
}

#ifndef APP_ARG_NUMERICAL_SIZE_CHARS
#define APP_ARG_NUMERICAL_SIZE_CHARS 15
#endif

static int
parse_arg_pos_lb(struct app_params app, const char *arg)
{
	uint32_t x;
	char *endpt;

	if (strnlen(arg, APP_ARG_NUMERICAL_SIZE_CHARS + 1) == APP_ARG_NUMERICAL_SIZE_CHARS + 1) {
		return -1;
	}

	errno = 0;
	x = strtoul(arg, &endpt, 10);
	if (errno != 0 || endpt == arg || *endpt != '\0'){
		return -2;
	}

	if (x >= 64) {
		return -3;
	}

	app.pos_lb = (uint8_t) x;

	return 0;
}

/* Parse the argument given in the command line of the application */
int
app_parse_args(struct app_params app, int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{"rx", 1, 0, 0},
		{"tx", 1, 0, 0},
		{"w", 1, 0, 0},
		{"lpm", 1, 0, 0},
		{"rsz", 1, 0, 0},
		{"bsz", 1, 0, 0},
		{"pos-lb", 1, 0, 0},
		{NULL, 0, 0, 0}
	};
	uint32_t arg_w = 0;
	uint32_t arg_rx = 0;
	uint32_t arg_tx = 0;
	uint32_t arg_lpm = 0;
	uint32_t arg_rsz = 0;
	uint32_t arg_bsz = 0;
	uint32_t arg_pos_lb = 0;

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "<>",
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* long options */
		case 0:
			if (!strcmp(lgopts[option_index].name, "rx")) {
				arg_rx = 1;
				ret = parse_arg_rx(app, optarg);
				if (ret) {
					printf("Incorrect value for --rx argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "tx")) {
				arg_tx = 1;
				ret = parse_arg_tx(app, optarg);
				if (ret) {
					printf("Incorrect value for --tx argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "w")) {
				arg_w = 1;
				ret = parse_arg_w(app, optarg);
				if (ret) {
					printf("Incorrect value for --w argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "lpm")) {
				arg_lpm = 1;
				ret = parse_arg_lpm(app, optarg);
				if (ret) {
					printf("Incorrect value for --lpm argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "rsz")) {
				arg_rsz = 1;
				ret = parse_arg_rsz(app, optarg);
				if (ret) {
					printf("Incorrect value for --rsz argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "bsz")) {
				arg_bsz = 1;
				ret = parse_arg_bsz(app, optarg);
				if (ret) {
					printf("Incorrect value for --bsz argument (%d)\n", ret);
					return -1;
				}
			}
			if (!strcmp(lgopts[option_index].name, "pos-lb")) {
				arg_pos_lb = 1;
				ret = parse_arg_pos_lb(app, optarg);
				if (ret) {
					printf("Incorrect value for --pos-lb argument (%d)\n", ret);
					return -1;
				}
			}
			break;

		default:
			return -1;
		}
	}

	/* Check that all mandatory arguments are provided */
	if ((arg_rx == 0) || (arg_tx == 0) || (arg_w == 0) || (arg_lpm == 0)){
		printf("Not all mandatory arguments are present\n");
		return -1;
	}

	/* Assign default values for the optional arguments not provided */
	if (arg_rsz == 0) {
		app.nic_rx_ring_size = APP_DEFAULT_NIC_RX_RING_SIZE;
		app.nic_tx_ring_size = APP_DEFAULT_NIC_TX_RING_SIZE;
		app.ring_rx_size = APP_DEFAULT_RING_RX_SIZE;
		app.ring_tx_size = APP_DEFAULT_RING_TX_SIZE;
	}

	if (arg_bsz == 0) {
		app.burst_size_io_rx_read = APP_DEFAULT_BURST_SIZE_IO_RX_READ;
		app.burst_size_io_rx_write = APP_DEFAULT_BURST_SIZE_IO_RX_WRITE;
		app.burst_size_io_tx_read = APP_DEFAULT_BURST_SIZE_IO_TX_READ;
		app.burst_size_io_tx_write = APP_DEFAULT_BURST_SIZE_IO_TX_WRITE;
		app.burst_size_worker_read = APP_DEFAULT_BURST_SIZE_WORKER_READ;
		app.burst_size_worker_write = APP_DEFAULT_BURST_SIZE_WORKER_WRITE;
	}

	if (arg_pos_lb == 0) {
		app.pos_lb = APP_DEFAULT_IO_RX_LB_POS;
	}

	/* Check cross-consistency of arguments */
	if ((ret = app_check_lpm_table(app)) < 0) {
		printf("At least one LPM rule is inconsistent (%d)\n", ret);
		return -1;
	}
	if (app_check_every_rx_port_is_tx_enabled(app) < 0) {
		printf("On LPM lookup miss, packet is sent back on the input port.\n");
		printf("At least one RX port is not enabled for TX.\n");
		return -2;
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 0; /* reset getopt lib */
	return ret;
}

int
app_get_nic_rx_queues_per_port(struct app_params app, uint8_t port)
{
	uint32_t i, count;

	if (port >= APP_MAX_NIC_PORTS) {
		return -1;
	}

	count = 0;
	for (i = 0; i < APP_MAX_RX_QUEUES_PER_NIC_PORT; i ++) {
		if (app.nic_rx_queue_mask[port][i] == 1) {
			count ++;
		}
	}

	return count;
}

int
app_get_lcore_for_nic_rx(struct app_params app, uint8_t port, uint8_t queue, uint32_t *lcore_out)
{
	uint32_t lcore;

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
		uint32_t i;

		if (app.lcore_params[lcore].type != e_APP_LCORE_IO) {
			continue;
		}

		const size_t n_queues = RTE_MIN(lp->rx.n_nic_queues,
		                                RTE_DIM(lp->rx.nic_queues));
		for (i = 0; i < n_queues; i ++) {
			if ((lp->rx.nic_queues[i].port == port) &&
			    (lp->rx.nic_queues[i].queue == queue)) {
				*lcore_out = lcore;
				return 0;
			}
		}
	}

	return -1;
}

int
app_get_lcore_for_nic_tx(struct app_params app, uint8_t port, uint32_t *lcore_out)
{
	uint32_t lcore;

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
		uint32_t i;

		if (app.lcore_params[lcore].type != e_APP_LCORE_IO) {
			continue;
		}

		const size_t n_ports = RTE_MIN(lp->tx.n_nic_ports,
		                               RTE_DIM(lp->tx.nic_ports));
		for (i = 0; i < n_ports; i ++) {
			if (lp->tx.nic_ports[i] == port) {
				*lcore_out = lcore;
				return 0;
			}
		}
	}

	return -1;
}

int
app_is_socket_used(struct app_params app, uint32_t socket)
{
	uint32_t lcore;

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type == e_APP_LCORE_DISABLED) {
			continue;
		}

		if (socket == rte_lcore_to_socket_id(lcore)) {
			return 1;
		}
	}

	return 0;
}

uint32_t
app_get_lcores_io_rx(struct app_params app)
{
	uint32_t lcore, count;

	count = 0;
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp_io->rx.n_nic_queues == 0)) {
			continue;
		}

		count ++;
	}

	return count;
}

uint32_t
app_get_lcores_worker(struct app_params app)
{
	uint32_t lcore, count;

	count = 0;
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		count ++;
	}

	if (count > APP_MAX_WORKER_LCORES) {
		rte_panic("Algorithmic error (too many worker lcores)\n");
		return 0;
	}

	return count;
}

void
app_print_params(struct app_params app)
{
	unsigned port, queue, lcore, rule, i, j;

	/* Print NIC RX configuration */
	printf("NIC RX ports: ");
	for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
		uint32_t n_rx_queues = app_get_nic_rx_queues_per_port(app, (uint8_t) port);

		if (n_rx_queues == 0) {
			continue;
		}

		printf("%u (", port);
		for (queue = 0; queue < APP_MAX_RX_QUEUES_PER_NIC_PORT; queue ++) {
			if (app.nic_rx_queue_mask[port][queue] == 1) {
				printf("%u ", queue);
			}
		}
		printf(")  ");
	}
	printf(";\n");

	/* Print I/O lcore RX params */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp->rx.n_nic_queues == 0)) {
			continue;
		}

		printf("I/O lcore %u (socket %u): ", lcore, rte_lcore_to_socket_id(lcore));

		printf("RX ports  ");
		for (i = 0; i < lp->rx.n_nic_queues; i ++) {
			printf("(%u, %u)  ",
				(unsigned) lp->rx.nic_queues[i].port,
				(unsigned) lp->rx.nic_queues[i].queue);
		}
		printf("; ");

		printf("Output rings  ");
		for (i = 0; i < lp->rx.n_rings; i ++) {
			printf("%p  ", lp->rx.rings[i]);
		}
		printf(";\n");
	}

	/* Print worker lcore RX params */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_worker *lp = &app.lcore_params[lcore].worker;

		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		printf("Worker lcore %u (socket %u) ID %u: ",
			lcore,
			rte_lcore_to_socket_id(lcore),
			(unsigned)lp->worker_id);

		printf("Input rings  ");
		for (i = 0; i < lp->n_rings_in; i ++) {
			printf("%p  ", lp->rings_in[i]);
		}

		printf(";\n");
	}

	printf("\n");

	/* Print NIC TX configuration */
	printf("NIC TX ports:  ");
	for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
		if (app.nic_tx_port_mask[port] == 1) {
			printf("%u  ", port);
		}
	}
	printf(";\n");

	/* Print I/O TX lcore params */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
		uint32_t n_workers = app_get_lcores_worker(app);

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		     (lp->tx.n_nic_ports == 0)) {
			continue;
		}

		printf("I/O lcore %u (socket %u): ", lcore, rte_lcore_to_socket_id(lcore));

		printf("Input rings per TX port  ");
		for (i = 0; i < lp->tx.n_nic_ports; i ++) {
			port = lp->tx.nic_ports[i];

			printf("%u (", port);
			for (j = 0; j < n_workers; j ++) {
				printf("%p  ", lp->tx.rings[port][j]);
			}
			printf(")  ");

		}

		printf(";\n");
	}

	/* Print worker lcore TX params */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_worker *lp = &app.lcore_params[lcore].worker;

		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		printf("Worker lcore %u (socket %u) ID %u: \n",
			lcore,
			rte_lcore_to_socket_id(lcore),
			(unsigned)lp->worker_id);

		printf("Output rings per TX port  ");
		for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
			if (lp->rings_out[port] != NULL) {
				printf("%u (%p)  ", port, lp->rings_out[port]);
			}
		}

		printf(";\n");
	}

	/* Print LPM rules */
	printf("LPM rules: \n");
	for (rule = 0; rule < app.n_lpm_rules; rule ++) {
		uint32_t ip = app.lpm_rules[rule].ip;
		uint8_t depth = app.lpm_rules[rule].depth;
		uint8_t if_out = app.lpm_rules[rule].if_out;

		printf("\t%u: %u.%u.%u.%u/%u => %u;\n",
			rule,
			(unsigned) (ip & 0xFF000000) >> 24,
			(unsigned) (ip & 0x00FF0000) >> 16,
			(unsigned) (ip & 0x0000FF00) >> 8,
			(unsigned) ip & 0x000000FF,
			(unsigned) depth,
			(unsigned) if_out
		);
	}

	/* Rings */
	printf("Ring sizes: NIC RX = %u; Worker in = %u; Worker out = %u; NIC TX = %u;\n",
		(unsigned) app.nic_rx_ring_size,
		(unsigned) app.ring_rx_size,
		(unsigned) app.ring_tx_size,
		(unsigned) app.nic_tx_ring_size);

	/* Bursts */
	printf("Burst sizes: I/O RX (rd = %u, wr = %u); Worker (rd = %u, wr = %u); I/O TX (rd = %u, wr = %u)\n",
		(unsigned) app.burst_size_io_rx_read,
		(unsigned) app.burst_size_io_rx_write,
		(unsigned) app.burst_size_worker_read,
		(unsigned) app.burst_size_worker_write,
		(unsigned) app.burst_size_io_tx_read,
		(unsigned) app.burst_size_io_tx_write);
}


/*
 * Initialization
 */

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode	= ETH_MQ_RX_RSS,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 1, /**< IP checksum offload enabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static void
app_assign_worker_ids(struct app_params app)
{
	uint32_t lcore, worker_id;

	/* Assign ID for each worker */
	worker_id = 0;
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore].worker;

		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		lp_worker->worker_id = worker_id;
		worker_id ++;
	}
}

static void
app_init_mbuf_pools(struct app_params app)
{
	unsigned socket, lcore;

	/* Init the buffer pools */
	for (socket = 0; socket < kAPPMAXSOCKET; socket ++) {
		char name[32];
		if (app_is_socket_used(app, socket) == 0) {
			continue;
		}

		snprintf(name, sizeof(name), "mbuf_pool_%u", socket);
		printf("Creating the mbuf pool for socket %u ...\n", socket);
		app.pools[socket] = rte_pktmbuf_pool_create(
			name, APP_DEFAULT_MEMPOOL_BUFFERS,
			APP_DEFAULT_MEMPOOL_CACHE_SIZE,
			0, APP_DEFAULT_MBUF_DATA_SIZE, socket);
		if (app.pools[socket] == NULL) {
			rte_panic("Cannot create mbuf pool on socket %u\n", socket);
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type == e_APP_LCORE_DISABLED) {
			continue;
		}

		socket = rte_lcore_to_socket_id(lcore);
		app.lcore_params[lcore].pool = app.pools[socket];
	}
}

static void
app_init_lpm_tables(struct app_params app)
{
	unsigned socket, lcore;

	/* Init the LPM tables */
	for (socket = 0; socket < kAPPMAXSOCKET; socket ++) {
		char name[32];
		uint32_t rule;

		if (app_is_socket_used(app, socket) == 0) {
			continue;
		}

		snprintf(name, sizeof(name), "lpm_table_%u", socket);
		printf("Creating the LPM table for socket %u ...\n", socket);
		app.lpm_tables[socket] = rte_lpm_create( name, socket, APP_MAX_LPM_RULES, 0);

		if (app.lpm_tables[socket] == NULL) {
			rte_panic("Unable to create LPM table on socket %u\n", socket);
		}

		for (rule = 0; rule < app.n_lpm_rules; rule ++) {
			int ret;

			ret = rte_lpm_add(app.lpm_tables[socket],
				app.lpm_rules[rule].ip,
				app.lpm_rules[rule].depth,
				app.lpm_rules[rule].if_out);

			if (ret < 0) {
				rte_panic("Unable to add entry %u (%x/%u => %u) to the LPM table on socket %u (%d)\n",
					(unsigned) rule,
					(unsigned) app.lpm_rules[rule].ip,
					(unsigned) app.lpm_rules[rule].depth,
					(unsigned) app.lpm_rules[rule].if_out,
					socket,
					ret);
			}
		}

	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		socket = rte_lcore_to_socket_id(lcore);
		app.lcore_params[lcore].worker.lpm_table = app.lpm_tables[socket];
	}
}

static void
app_init_rings_rx(struct app_params app)
{
	unsigned lcore;

	/* Initialize the rings for the RX side */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;
		unsigned socket_io, lcore_worker;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp_io->rx.n_nic_queues == 0)) {
			continue;
		}

		socket_io = rte_lcore_to_socket_id(lcore);

		for (lcore_worker = 0; lcore_worker < APP_MAX_LCORES; lcore_worker ++) {
			char name[32];
			struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore_worker].worker;
			struct rte_ring *ring = NULL;

			if (app.lcore_params[lcore_worker].type != e_APP_LCORE_WORKER) {
				continue;
			}

			printf("Creating ring to connect I/O lcore %u (socket %u) with worker lcore %u ...\n",
				lcore,
				socket_io,
				lcore_worker);
			snprintf(name, sizeof(name), "app_ring_rx_s%u_io%u_w%u",
				socket_io,
				lcore,
				lcore_worker);
			ring = rte_ring_create(
				name,
				app.ring_rx_size,
				socket_io,
				RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				rte_panic("Cannot create ring to connect I/O core %u with worker core %u\n",
					lcore,
					lcore_worker);
			}

			lp_io->rx.rings[lp_io->rx.n_rings] = ring;
			lp_io->rx.n_rings ++;

			lp_worker->rings_in[lp_worker->n_rings_in] = ring;
			lp_worker->n_rings_in ++;
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp_io->rx.n_nic_queues == 0)) {
			continue;
		}

		if (lp_io->rx.n_rings != app_get_lcores_worker(app)) {
			rte_panic("Algorithmic error (I/O RX rings)\n");
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore].worker;

		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		if (lp_worker->n_rings_in != app_get_lcores_io_rx(app)) {
			rte_panic("Algorithmic error (worker input rings)\n");
		}
	}
}

static void
app_init_rings_tx(struct app_params app)
{
	unsigned lcore;

	/* Initialize the rings for the TX side */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore].worker;
		unsigned port;

		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
			char name[32];
			struct app_lcore_params_io *lp_io = NULL;
			struct rte_ring *ring;
			uint32_t socket_io, lcore_io;

			if (app.nic_tx_port_mask[port] == 0) {
				continue;
			}

			if (app_get_lcore_for_nic_tx(app, (uint8_t) port, &lcore_io) < 0) {
				rte_panic("Algorithmic error (no I/O core to handle TX of port %u)\n",
					port);
			}

			lp_io = &app.lcore_params[lcore_io].io;
			socket_io = rte_lcore_to_socket_id(lcore_io);

			printf("Creating ring to connect worker lcore %u with TX port %u (through I/O lcore %u) (socket %u) ...\n",
				lcore, port, (unsigned)lcore_io, (unsigned)socket_io);
			snprintf(name, sizeof(name), "app_ring_tx_s%u_w%u_p%u", socket_io, lcore, port);
			ring = rte_ring_create(
				name,
				app.ring_tx_size,
				socket_io,
				RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				rte_panic("Cannot create ring to connect worker core %u with TX port %u\n",
					lcore,
					port);
			}

			lp_worker->rings_out[port] = ring;
			lp_io->tx.rings[port][lp_worker->worker_id] = ring;
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;
		unsigned i;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp_io->tx.n_nic_ports == 0)) {
			continue;
		}

		for (i = 0; i < lp_io->tx.n_nic_ports; i ++){
			unsigned port, j;

			port = lp_io->tx.nic_ports[i];
			for (j = 0; j < app_get_lcores_worker(app); j ++) {
				if (lp_io->tx.rings[port][j] == NULL) {
					rte_panic("Algorithmic error (I/O TX rings)\n");
				}
			}
		}
	}
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(struct app_params app, uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint32_t n_rx_queues, n_tx_queues;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			n_rx_queues = app_get_nic_rx_queues_per_port(app, portid);
			n_tx_queues = app.nic_tx_port_mask[portid];
			if ((n_rx_queues == 0) && (n_tx_queues == 0))
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
							(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
app_init_nics(struct app_params app)
{
	unsigned socket;
	uint32_t lcore;
	uint8_t port, queue;
	int ret;
	uint32_t n_rx_queues, n_tx_queues;

	/* Init NIC ports and queues, then start the ports */
	for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
		struct rte_mempool *pool;

		n_rx_queues = app_get_nic_rx_queues_per_port(app, port);
		n_tx_queues = app.nic_tx_port_mask[port];

		if ((n_rx_queues == 0) && (n_tx_queues == 0)) {
			continue;
		}

		/* Init port */
		printf("Initializing NIC port %u ...\n", (unsigned) port);
		ret = rte_eth_dev_configure(
			port,
			(uint8_t) n_rx_queues,
			(uint8_t) n_tx_queues,
			&port_conf);
		if (ret < 0) {
			rte_panic("Cannot init NIC port %u (%d)\n", (unsigned) port, ret);
		}
		rte_eth_promiscuous_enable(port);

		/* Init RX queues */
		for (queue = 0; queue < APP_MAX_RX_QUEUES_PER_NIC_PORT; queue ++) {
			if (app.nic_rx_queue_mask[port][queue] == 0) {
				continue;
			}

			app_get_lcore_for_nic_rx(app, port, queue, &lcore);
			socket = rte_lcore_to_socket_id(lcore);
			pool = app.lcore_params[lcore].pool;

			printf("Initializing NIC port %u RX queue %u ...\n",
				(unsigned) port,
				(unsigned) queue);
			ret = rte_eth_rx_queue_setup(
				port,
				queue,
				(uint16_t) app.nic_rx_ring_size,
				socket,
				NULL,
				pool);
			if (ret < 0) {
				rte_panic("Cannot init RX queue %u for port %u (%d)\n",
					(unsigned) queue,
					(unsigned) port,
					ret);
			}
		}

		/* Init TX queues */
		if (app.nic_tx_port_mask[port] == 1) {
			app_get_lcore_for_nic_tx(app, port, &lcore);
			socket = rte_lcore_to_socket_id(lcore);
			printf("Initializing NIC port %u TX queue 0 ...\n",
				(unsigned) port);
			ret = rte_eth_tx_queue_setup(
				port,
				0,
				(uint16_t) app.nic_tx_ring_size,
				socket,
				NULL);
			if (ret < 0) {
				rte_panic("Cannot init TX queue 0 for port %d (%d)\n",
					port,
					ret);
			}
		}

		/* Start port */
		ret = rte_eth_dev_start(port);
		if (ret < 0) {
			rte_panic("Cannot start port %d (%d)\n", port, ret);
		}
	}

	check_all_ports_link_status(app, APP_MAX_NIC_PORTS, (~0x0));
}

void
app_init(struct app_params app)
{
	app_assign_worker_ids(app);
	app_init_mbuf_pools(app);
	//app_init_lpm_tables(app);
	app_init_rings_rx(app);
	app_init_rings_tx(app);
	app_init_nics(app);

	printf("Initialization completed.\n");
}


/*
 * Runtime process
 */

#ifndef APP_LCORE_IO_FLUSH
#define APP_LCORE_IO_FLUSH           1000000
#endif

#ifndef APP_LCORE_WORKER_FLUSH
#define APP_LCORE_WORKER_FLUSH       1000000
#endif

#ifndef APP_STATS
#define APP_STATS                    1000000
#endif

#define APP_IO_RX_DROP_ALL_PACKETS   0
#define APP_WORKER_DROP_ALL_PACKETS  0
#define APP_IO_TX_DROP_ALL_PACKETS   0

#ifndef APP_IO_RX_PREFETCH_ENABLE
#define APP_IO_RX_PREFETCH_ENABLE    1
#endif

#ifndef APP_WORKER_PREFETCH_ENABLE
#define APP_WORKER_PREFETCH_ENABLE   1
#endif

#ifndef APP_IO_TX_PREFETCH_ENABLE
#define APP_IO_TX_PREFETCH_ENABLE    1
#endif

#if APP_IO_RX_PREFETCH_ENABLE
#define APP_IO_RX_PREFETCH0(p)       rte_prefetch0(p)
#define APP_IO_RX_PREFETCH1(p)       rte_prefetch1(p)
#else
#define APP_IO_RX_PREFETCH0(p)
#define APP_IO_RX_PREFETCH1(p)
#endif

#if APP_WORKER_PREFETCH_ENABLE
#define APP_WORKER_PREFETCH0(p)      rte_prefetch0(p)
#define APP_WORKER_PREFETCH1(p)      rte_prefetch1(p)
#else
#define APP_WORKER_PREFETCH0(p)
#define APP_WORKER_PREFETCH1(p)
#endif

#if APP_IO_TX_PREFETCH_ENABLE
#define APP_IO_TX_PREFETCH0(p)       rte_prefetch0(p)
#define APP_IO_TX_PREFETCH1(p)       rte_prefetch1(p)
#else
#define APP_IO_TX_PREFETCH0(p)
#define APP_IO_TX_PREFETCH1(p)
#endif

static inline void
app_lcore_io_rx_buffer_to_send (
	struct app_lcore_params_io *lp,
	uint32_t worker,
	struct rte_mbuf *mbuf,
	uint32_t bsz)
{
	uint32_t pos;
	int ret;

	pos = lp->rx.mbuf_out[worker].n_mbufs;
	lp->rx.mbuf_out[worker].array[pos ++] = mbuf;
	if (likely(pos < bsz)) {
		lp->rx.mbuf_out[worker].n_mbufs = pos;
		return;
	}

	ret = rte_ring_sp_enqueue_bulk(
		lp->rx.rings[worker],
		(void **) lp->rx.mbuf_out[worker].array,
		bsz);

	if (unlikely(ret == -ENOBUFS)) {
		uint32_t k;
		for (k = 0; k < bsz; k ++) {
			struct rte_mbuf *m = lp->rx.mbuf_out[worker].array[k];
			rte_pktmbuf_free(m);
		}
	}

	lp->rx.mbuf_out[worker].n_mbufs = 0;
	lp->rx.mbuf_out_flush[worker] = 0;

#if APP_STATS
	lp->rx.rings_iters[worker] ++;
	if (likely(ret == 0)) {
		lp->rx.rings_count[worker] ++;
	}
	if (unlikely(lp->rx.rings_iters[worker] == APP_STATS)) {
		unsigned lcore = rte_lcore_id();

		printf("\tI/O RX %u out (worker %u): enq success rate = %.2f\n",
			lcore,
			(unsigned)worker,
			((double) lp->rx.rings_count[worker]) / ((double) lp->rx.rings_iters[worker]));
		lp->rx.rings_iters[worker] = 0;
		lp->rx.rings_count[worker] = 0;
	}
#endif
}

static inline int
app_lcore_io_rx(
	struct app_lcore_params_io *lp,
	uint32_t n_workers,
	uint32_t bsz_rd,
	uint32_t bsz_wr,
	uint8_t pos_lb)
{
	struct rte_mbuf *mbuf_1_0, *mbuf_1_1, *mbuf_2_0, *mbuf_2_1;
	uint8_t *data_1_0, *data_1_1 = NULL;
	uint32_t i;
        uint8_t *t;
        int cntpkt = 0 ;

	for (i = 0; i < lp->rx.n_nic_queues; i ++) {
		uint8_t port = lp->rx.nic_queues[i].port;
		uint8_t queue = lp->rx.nic_queues[i].queue;
		uint32_t n_mbufs, j;

		n_mbufs = rte_eth_rx_burst(
			port,
			queue,
			lp->rx.mbuf_in.array,
			(uint16_t) bsz_rd);

		if (unlikely(n_mbufs == 0)) {
			continue;
		}

#if APP_STATS
		lp->rx.nic_queues_iters[i] ++;
		lp->rx.nic_queues_count[i] += n_mbufs;
		if (unlikely(lp->rx.nic_queues_iters[i] == APP_STATS)) {
			struct rte_eth_stats stats;
			unsigned lcore = rte_lcore_id();

			rte_eth_stats_get(port, &stats);

                         printf("I/O RX %u in (NIC port %u): Received packets = %"PRIu64"; Sent packets = %"PRIu64"; "
                                 "Error packets = %"PRIu64";  NIC drop ratio = %.2f; Avg burst size = %.2f\n",
                                 lcore,
				(unsigned) port,
                                stats.ipackets,
                                stats.opackets,
                                stats.ierrors,
				(double) stats.imissed / (double) (stats.imissed + stats.ipackets),
				((double) lp->rx.nic_queues_count[i]) / ((double) lp->rx.nic_queues_iters[i]));
			lp->rx.nic_queues_iters[i] = 0;
			lp->rx.nic_queues_count[i] = 0;
		}
                cntpkt += lp->rx.nic_queues_iters[i];
#endif

#if APP_IO_RX_DROP_ALL_PACKETS
		for (j = 0; j < n_mbufs; j ++) {
			struct rte_mbuf *pkt = lp->rx.mbuf_in.array[j];
			rte_pktmbuf_free(pkt);
		}

		continue;
#endif

		mbuf_1_0 = lp->rx.mbuf_in.array[0];
		mbuf_1_1 = lp->rx.mbuf_in.array[1];
		data_1_0 = rte_pktmbuf_mtod(mbuf_1_0, uint8_t *);
		if (likely(n_mbufs > 1)) {
			data_1_1 = rte_pktmbuf_mtod(mbuf_1_1, uint8_t *);
		}

		mbuf_2_0 = lp->rx.mbuf_in.array[2];
		mbuf_2_1 = lp->rx.mbuf_in.array[3];
		APP_IO_RX_PREFETCH0(mbuf_2_0);
		APP_IO_RX_PREFETCH0(mbuf_2_1);

		for (j = 0; j + 3 < n_mbufs; j += 2) {
			struct rte_mbuf *mbuf_0_0, *mbuf_0_1;
			uint8_t *data_0_0, *data_0_1;
			uint32_t worker_0, worker_1;

			mbuf_0_0 = mbuf_1_0;
			mbuf_0_1 = mbuf_1_1;
			data_0_0 = data_1_0;
			data_0_1 = data_1_1;

			mbuf_1_0 = mbuf_2_0;
			mbuf_1_1 = mbuf_2_1;
			data_1_0 = rte_pktmbuf_mtod(mbuf_2_0, uint8_t *);
			data_1_1 = rte_pktmbuf_mtod(mbuf_2_1, uint8_t *);
			APP_IO_RX_PREFETCH0(data_1_0);
			APP_IO_RX_PREFETCH0(data_1_1);

			mbuf_2_0 = lp->rx.mbuf_in.array[j+4];
			mbuf_2_1 = lp->rx.mbuf_in.array[j+5];
			APP_IO_RX_PREFETCH0(mbuf_2_0);
			APP_IO_RX_PREFETCH0(mbuf_2_1);

			worker_0 = data_0_0[pos_lb] & (n_workers - 1);
			worker_1 = data_0_1[pos_lb] & (n_workers - 1);

			app_lcore_io_rx_buffer_to_send(lp, worker_0, mbuf_0_0, bsz_wr);
			app_lcore_io_rx_buffer_to_send(lp, worker_1, mbuf_0_1, bsz_wr);
		}

		/* Handle the last 1, 2 (when n_mbufs is even) or 3 (when n_mbufs is odd) packets  */
		for ( ; j < n_mbufs; j += 1) {
			struct rte_mbuf *mbuf;
			uint8_t *data;
			uint32_t worker;

			mbuf = mbuf_1_0;
			mbuf_1_0 = mbuf_1_1;
			mbuf_1_1 = mbuf_2_0;
			mbuf_2_0 = mbuf_2_1;

			data = rte_pktmbuf_mtod(mbuf, uint8_t *);

			APP_IO_RX_PREFETCH0(mbuf_1_0);

			worker = data[pos_lb] & (n_workers - 1);

			app_lcore_io_rx_buffer_to_send(lp, worker, mbuf, bsz_wr);
		}
	}

        return cntpkt;
}

static inline void
app_lcore_io_rx_flush(struct app_lcore_params_io *lp, uint32_t n_workers)
{
	uint32_t worker;

	for (worker = 0; worker < n_workers; worker ++) {
		int ret;

		if (likely((lp->rx.mbuf_out_flush[worker] == 0) ||
		           (lp->rx.mbuf_out[worker].n_mbufs == 0))) {
			lp->rx.mbuf_out_flush[worker] = 1;
			continue;
		}

		ret = rte_ring_sp_enqueue_bulk(
			lp->rx.rings[worker],
			(void **) lp->rx.mbuf_out[worker].array,
			lp->rx.mbuf_out[worker].n_mbufs);

		if (unlikely(ret < 0)) {
			uint32_t k;
			for (k = 0; k < lp->rx.mbuf_out[worker].n_mbufs; k ++) {
				struct rte_mbuf *pkt_to_free = lp->rx.mbuf_out[worker].array[k];
				rte_pktmbuf_free(pkt_to_free);
			}
		}

		lp->rx.mbuf_out[worker].n_mbufs = 0;
		lp->rx.mbuf_out_flush[worker] = 1;
	}
}

static inline void
app_lcore_io_tx(
	struct app_lcore_params_io *lp,
	uint32_t n_workers,
	uint32_t bsz_rd,
	uint32_t bsz_wr, 
        int cntpkt)
{
	uint32_t worker;

	for (worker = 0; worker < n_workers; worker ++) {
		uint32_t i;

		for (i = 0; i < lp->tx.n_nic_ports; i ++) {
			uint8_t port = lp->tx.nic_ports[i];
			struct rte_ring *ring = lp->tx.rings[port][worker];
			uint32_t n_mbufs, n_pkts;
			int ret;

			n_mbufs = lp->tx.mbuf_out[port].n_mbufs;
			ret = rte_ring_sc_dequeue_bulk(
				ring,
				(void **) &lp->tx.mbuf_out[port].array[n_mbufs],
				bsz_rd);

			if (unlikely(ret == -ENOENT)) {
				continue;
			}

			n_mbufs += bsz_rd;

#if APP_IO_TX_DROP_ALL_PACKETS
			{
				uint32_t j;
				APP_IO_TX_PREFETCH0(lp->tx.mbuf_out[port].array[0]);
				APP_IO_TX_PREFETCH0(lp->tx.mbuf_out[port].array[1]);

				for (j = 0; j < n_mbufs; j ++) {
					if (likely(j < n_mbufs - 2)) {
						APP_IO_TX_PREFETCH0(lp->tx.mbuf_out[port].array[j + 2]);
					}

					rte_pktmbuf_free(lp->tx.mbuf_out[port].array[j]);
				}

				lp->tx.mbuf_out[port].n_mbufs = 0;

				continue;
			}
#endif

			if (unlikely(n_mbufs < bsz_wr)) {
				lp->tx.mbuf_out[port].n_mbufs = n_mbufs;
				continue;
			}

			n_pkts = rte_eth_tx_burst(
				port,
				0,
				lp->tx.mbuf_out[port].array,
				(uint16_t) n_mbufs);

//#if APP_STATS
			lp->tx.nic_ports_iters[port] ++;
			lp->tx.nic_ports_count[port] += n_pkts;
			if (unlikely(lp->tx.nic_ports_iters[port] == cntpkt)) {
				unsigned lcore = rte_lcore_id();

				printf("\t\t\tI/O TX %u out (port %u): avg burst size = %.2f\n",
					lcore,
					(unsigned) port,
					((double) lp->tx.nic_ports_count[port]) / ((double) lp->tx.nic_ports_iters[port]));
				lp->tx.nic_ports_iters[port] = 0;
				lp->tx.nic_ports_count[port] = 0;
			}
//#endif

			if (unlikely(n_pkts < n_mbufs)) {
				uint32_t k;
				for (k = n_pkts; k < n_mbufs; k ++) {
					struct rte_mbuf *pkt_to_free = lp->tx.mbuf_out[port].array[k];
					rte_pktmbuf_free(pkt_to_free);
				}
			}
			lp->tx.mbuf_out[port].n_mbufs = 0;
			lp->tx.mbuf_out_flush[port] = 0;
		}
	}
}

static inline void
app_lcore_io_tx_flush(struct app_lcore_params_io *lp)
{
	uint8_t port;

	for (port = 0; port < lp->tx.n_nic_ports; port ++) {
		uint32_t n_pkts;

		if (likely((lp->tx.mbuf_out_flush[port] == 0) ||
		           (lp->tx.mbuf_out[port].n_mbufs == 0))) {
			lp->tx.mbuf_out_flush[port] = 1;
			continue;
		}

		n_pkts = rte_eth_tx_burst(
			port,
			0,
			lp->tx.mbuf_out[port].array,
			(uint16_t) lp->tx.mbuf_out[port].n_mbufs);

		if (unlikely(n_pkts < lp->tx.mbuf_out[port].n_mbufs)) {
			uint32_t k;
			for (k = n_pkts; k < lp->tx.mbuf_out[port].n_mbufs; k ++) {
				struct rte_mbuf *pkt_to_free = lp->tx.mbuf_out[port].array[k];
				rte_pktmbuf_free(pkt_to_free);
			}
		}

		lp->tx.mbuf_out[port].n_mbufs = 0;
		lp->tx.mbuf_out_flush[port] = 1;
	}
}

static void
app_lcore_main_loop_io(struct app_params app)
{
	uint32_t lcore = rte_lcore_id();
	struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
	uint32_t n_workers = app_get_lcores_worker(app);
	uint64_t i = 0;

	uint32_t bsz_rx_rd = app.burst_size_io_rx_read;
	uint32_t bsz_rx_wr = app.burst_size_io_rx_write;
	uint32_t bsz_tx_rd = app.burst_size_io_tx_read;
	uint32_t bsz_tx_wr = app.burst_size_io_tx_write;

	uint8_t pos_lb = app.pos_lb;

	for ( ; ; ) {
		if (APP_LCORE_IO_FLUSH && (unlikely(i == APP_LCORE_IO_FLUSH))) {
			if (likely(lp->rx.n_nic_queues > 0)) {
				app_lcore_io_rx_flush(lp, n_workers);
			}

			if (likely(lp->tx.n_nic_ports > 0)) {
				app_lcore_io_tx_flush(lp);
			}

			i = 0;
		}

		if (likely(lp->rx.n_nic_queues > 0)) {
			app.cntPkt = app_lcore_io_rx(lp, n_workers, bsz_rx_rd, bsz_rx_wr, pos_lb);
		}

		if (likely(lp->tx.n_nic_ports > 0)) {
			app_lcore_io_tx(lp, n_workers, bsz_tx_rd, bsz_tx_wr, app.cntPkt);
		}

		i ++;
	}
}

static inline void
app_lcore_worker(
	struct app_lcore_params_worker *lp,
	uint32_t bsz_rd,
	uint32_t bsz_wr, 
        int cntpkt)
{
	uint32_t i;

	for (i = 0; i < lp->n_rings_in; i ++) {
		struct rte_ring *ring_in = lp->rings_in[i];
		uint32_t j;
		int ret;

		ret = rte_ring_sc_dequeue_bulk(
			ring_in,
			(void **) lp->mbuf_in.array,
			bsz_rd);

		if (unlikely(ret == -ENOENT)) {
			continue;
		}

#if APP_WORKER_DROP_ALL_PACKETS
		for (j = 0; j < bsz_rd; j ++) {
			struct rte_mbuf *pkt = lp->mbuf_in.array[j];
			rte_pktmbuf_free(pkt);
		}

		continue;
#endif

		APP_WORKER_PREFETCH1(rte_pktmbuf_mtod(lp->mbuf_in.array[0], unsigned char *));
		APP_WORKER_PREFETCH0(lp->mbuf_in.array[1]);

		for (j = 0; j < bsz_rd; j ++) {
			struct rte_mbuf *pkt;
			struct ipv4_hdr *ipv4_hdr;
			uint32_t ipv4_dst, pos;
			uint8_t port;

			if (likely(j < bsz_rd - 1)) {
				APP_WORKER_PREFETCH1(rte_pktmbuf_mtod(lp->mbuf_in.array[j+1], unsigned char *));
			}
			if (likely(j < bsz_rd - 2)) {
				APP_WORKER_PREFETCH0(lp->mbuf_in.array[j+2]);
			}

			pkt = lp->mbuf_in.array[j];
			ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, sizeof(struct ether_hdr));	
                        ipv4_dst = rte_be_to_cpu_32(ipv4_hdr->dst_addr);

			if (unlikely(rte_lpm_lookup(lp->lpm_table, ipv4_dst, &port) != 0)) {
				port = pkt->port;
			}

			pos = lp->mbuf_out[port].n_mbufs;

			lp->mbuf_out[port].array[pos ++] = pkt;
			if (likely(pos < bsz_wr)) {
				lp->mbuf_out[port].n_mbufs = pos;
				continue;
			}

			ret = rte_ring_sp_enqueue_bulk(
				lp->rings_out[port],
				(void **) lp->mbuf_out[port].array,
				bsz_wr);

#if APP_STATS
			lp->rings_out_iters[port] ++;
			if (ret == 0) {
				lp->rings_out_count[port] += 1;
			}
			if (lp->rings_out_iters[port] == cntpkt){
				printf("\t\tWorker %u out (NIC port %u): enq success rate = %.2f\n",
					(unsigned) lp->worker_id,
					(unsigned) port,
					((double) lp->rings_out_count[port]) / ((double) lp->rings_out_iters[port]));
				lp->rings_out_iters[port] = 0;
				lp->rings_out_count[port] = 0;
			}
#endif

			if (unlikely(ret == -ENOBUFS)) {
				uint32_t k;
				for (k = 0; k < bsz_wr; k ++) {
					struct rte_mbuf *pkt_to_free = lp->mbuf_out[port].array[k];
					rte_pktmbuf_free(pkt_to_free);
				}
			}

			lp->mbuf_out[port].n_mbufs = 0;
			lp->mbuf_out_flush[port] = 0;
		}
	}
}

static inline void
app_lcore_worker_flush(struct app_lcore_params_worker *lp)
{
	uint32_t port;

	for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
		int ret;

		if (unlikely(lp->rings_out[port] == NULL)) {
			continue;
		}

		if (likely((lp->mbuf_out_flush[port] == 0) ||
		           (lp->mbuf_out[port].n_mbufs == 0))) {
			lp->mbuf_out_flush[port] = 1;
			continue;
		}

		ret = rte_ring_sp_enqueue_bulk(
			lp->rings_out[port],
			(void **) lp->mbuf_out[port].array,
			lp->mbuf_out[port].n_mbufs);

		if (unlikely(ret < 0)) {
			uint32_t k;
			for (k = 0; k < lp->mbuf_out[port].n_mbufs; k ++) {
				struct rte_mbuf *pkt_to_free = lp->mbuf_out[port].array[k];
				rte_pktmbuf_free(pkt_to_free);
			}
		}

		lp->mbuf_out[port].n_mbufs = 0;
		lp->mbuf_out_flush[port] = 1;
	}
}

static void
app_lcore_main_loop_worker(struct app_params app) {
	uint32_t lcore = rte_lcore_id();
	struct app_lcore_params_worker *lp = &app.lcore_params[lcore].worker;
	uint64_t i = 0;

	uint32_t bsz_rd = app.burst_size_worker_read;
	uint32_t bsz_wr = app.burst_size_worker_write;

	for ( ; ; ) {
		if (APP_LCORE_WORKER_FLUSH && (unlikely(i == APP_LCORE_WORKER_FLUSH))) {
			app_lcore_worker_flush(lp);
			i = 0;
		}

		app_lcore_worker(lp, bsz_rd, bsz_wr, app.cntPkt);

		i ++;
	}
}

int
dpdk_daq_main_loop(struct app_params app)
{
	struct app_lcore_params *lp;
	unsigned lcore;

	lcore = rte_lcore_id();
	lp = &app.lcore_params[lcore];

	if (lp->type == e_APP_LCORE_IO) {
		printf("Logical core %u (I/O) main loop.\n", lcore);
		app_lcore_main_loop_io(app);
	}

	if (lp->type == e_APP_LCORE_WORKER) {
		printf("Logical core %u (worker %u) main loop.\n",
			lcore,
			(unsigned) lp->worker.worker_id);
		app_lcore_main_loop_worker(app);
	}

	return 0;
}

/*
 * DPDK - DAQ process
 */
struct dpdk_stat {
    uint8_t recv; // number of packets received
    uint8_t drop; // number of packets dropped
};
/* DPDK DAQ Context */
typedef struct _Dpdk_Context_t 
{
    DAQ_Mode mode;
    char *devices[32];
    unsigned num_devices;
    int snaplen;
    char errbuf[1024];
    u_char *pkt_buffer;
    u_char *inj_buffer;
    u_char *user_data;
    int packets;
    int app_stats;
    u_int breakloop;
    int promisc_flag;
    int timeout;
    DAQ_Analysis_Func_t analysis_func;
    uint32_t netmask;
    DAQ_Stats_t stats;
    DAQ_State state;
    struct app_params app;
    uint64_t base_recv[DAQ_DPDK_MAX_NUM_DEVICES];
    uint64_t base_drop[DAQ_DPDK_MAX_NUM_DEVICES];
} Dpdk_Context_t;

static void dpdk_daq_reset_stats(void *handle);
static int dpdk_daq_set_filter(void *handle, const char *filter);

/*
 *  @dpdk_daq_open:
 *  @purpose: create DPDK ring_handle and necessary buffers and objects for devices
 *  @params: Dpdk_Context_t *context: ptr DPDK context
 *           int id : device id
 *  @return: 0 if no error
 *           -1 if failed.
 */

static int dpdk_daq_open(Dpdk_Context_t *context, int id) {
    return(0);
}

/*
 * @update_hw_stats
 * @purpose: updating hardware statistic
 * @params: 
 *        Dpdk_Context_t *context: ptr to context.
 * @return:
 *        DAQ_SUCCESS: if no error.
 *        
 */
static int update_hw_stats(Dpdk_Context_t *context)
{
    /*
    struct dpdk_stat ds;
    int i;

    for (i = 0; i < context->num_devices; i++)
        if (context->ring_handles[i] == NULL)
            return DAQ_SUCCESS;

    context->stats.hw_packets_received = 0;
    context->stats.hw_packets_dropped = 0;

    for (i = 0; i < context->num_devices; i++) 
    {
        memset(&ds, 0, sizeof(struct dpdk_stat));
        if (dpdk_stats(context->ring_handles[i].&ds) < 0) {
            DPE(context->errbuf, "%s: dpdk_stats error [ring_idx = %d]", __FUNCTION__, i);
            return DAQ_ERROR;
        }

        context->stats.hw_packets_received += (ds.recv - context->base_recv[i]);
        context->stats.hw_packets_dropped  += (ds.drop - context->base_drop[i]);
    }
*/
    return DAQ_SUCCESS;
}

static void dpdk_daq_reload(Dpdk_Context_t *context){ 
    int i;
    printf("Not supported yet!\n");
}

static void parse_dpdk_args(const char *args, int *dst_argc, char ***dst_argv)
{
    char *buf = strdup(args);
    int num = 1;
    char *delim;
    char **argv = calloc(num, sizeof(char *));

    if (!buf || !argv)
        printf("Cannot allocate memory!\n");

    argv[0] = buf;
    while(1) { 
        delim = strchr(argv[num -1], ' ');
        if (delim == NULL)
            break;

        argv = realloc(argv, (num + 1) * sizeof (char *));
        if (!argv)
            printf("Cannot allocate memory!\n");
        argv[num] = delim + 1;
        *delim = 0;
        num++;
    }

    *dst_argc = num;
    *dst_argv = argv;
    return;
}


static int daq_init_dpdk(void)
{
    char **dpdk_argv;
    int dpdk_argc;
    char *env;
    char *new_env;
    int core_mask, i, save_optind;

    env = getenv("ODP_PLATFORM_PARAMS");
    if (env == NULL)
        return -1;
    for (i = 0, core_mask =0; i < odp_cpu_count(); i++)
        core_mask += (0x1 << i);
    new_env = calloc(1, strlen(env) + strlen("odpdpdk -c") + sizeof(core_mask) + 1);
    sprintf(new_env, "odpdpdk -c 0x%x %s",core_mask, env);
    parse_dpdk_args(new_env, &dpdk_argc, &dpdk_argv);
    for (i= 0; i < dpdk_argc; ++i)
        printf("arg[%d]: %s\n", i, dpdk_argv[i]);
    fflush(stdout);
    free(new_env);

    printf("Initializing DPDK EAL ...\n");
    i = rte_eal_init(dpdk_argc, dpdk_argv);
    free(dpdk_argv[0]);
    free(dpdk_argv);
    if ( i < 0) {
        printf("Cannot init the Intel DPDK EAL!\n");
        return -1;
    } else {
        printf("Some DPDK args were not processed!\n");
        printf("Passed: %d consumed %d\n", dpdk_argc, i);
    }

    printf("rte_eal_init DONE!\n");
    return 0;
}

/*
 * @dpdk_daq_initialize:
 * @purpose: Initialize DPDK context (objects, I/O devices, ...) & DAQ Dict
 * @params: const DA_Config_t *config : ptr to DAQ config
 *          void **ctx_ptr: ptr to context.
 *          char **errbuf: buffer to handle error case.
 *          size_t len: size of errbuf
 *  @return: DAQ_SUCCESS if no error.
 *           DAQ_ERROR if failed.
 */
static int dpdk_daq_initialize(const DAQ_Config_t *config, 
                                void **ctxt_ptr, char *errbuf, size_t len)
{
    Dpdk_Context_t *context;
    DAQ_Dict* entry;
    int ret;
    uint32_t default_net = 0xFFFFFF00;

    ret = odp_init_global(NULL, NULL); 
    if (ret < 0)
        return -1;
   
    /*
    ret = app_parse_args(context->app, argc, (char **)argv);
    if (ret < 0)
        return -1;
    */

    printf("Initializing context apps ...");
    context = calloc(1, sizeof(Dpdk_Context_t));
    if (!context) {
        snprintf(errbuf, len, "%s: couldn't allocate memory for the new DPDK context!", __FUNCTION__);
    }

    /* other context init */
    context->mode = config->mode;
    context->pkt_buffer = NULL;
    context->inj_buffer = NULL;
    context->snaplen = config->snaplen;
    context->promisc_flag = (config->flags & DAQ_CFG_PROMISC);
    context->timeout = (config->timeout > 0) ? (int)config->timeout:-1;
    context->devices[DAQ_DPDK_PASSIVE_DEV_IDX] =  strdup(config->name);

    /*
    if (context->mode == DAQ_MODE_INLINE) {
        app_init(context->app);
        app_print_params(context->app);
    }*/
    context->app.cntPkt = APP_STATS;
    context->netmask = htonl(default_net);
    context->state = DAQ_STATE_INITIALIZED;
    printf("Finish Init!\n");
    *ctxt_ptr = context;
    return DAQ_SUCCESS;
}

/*
 * @dpdk_daq_set_filter
 */
static int dpdk_daq_set_filter(void *handle, const char *filter)
{
    return DAQ_SUCCESS;
}

/*
 * @dpdk_daq_start
 * @purpose: Start packet capture
 */
static int dpdk_daq_start(void *handle)
{
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    
    //dpdk_daq_reset_stats(context);
    context->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;
}

/*
 * @dpdk_daq_acquire
 * @purpose: Acquire up to <cnt> packets and call <callback> for each with <user> as
 *           the final argument.
 * @params:
 *          handle: context variable
 *          cnt: counting packets
 *          callback: To get callback to DAQ Analysis function
 *          metaback: 
 *          user
 * @return:
 */
static int dpdk_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback,
                            DAQ_Meta_Func_t metaback, void *user)
{
    uint32_t lcore_id;
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    context->analysis_func = callback;
    context->user_data = user;
    context->packets = 0;
    context->breakloop = 0;
    printf("ACQUIRING PKTS!\n");
    // packet_acquiring
    while (context->packets < cnt || cnt <= 0)
    {
        if(context->breakloop) {
            context->breakloop = 0;
            return 0;
        } 
        /*
        rte_eal_mp_remote_launch(dpdk_daq_main_loop, NULL, CALL_MASTER);
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            if (rte_eal_wait_lcore(lcore_id) < 0)
                return -1;
        }
        */
        context->packets += context->app.cntPkt; 
    }

    return 0;
}

/*
 * @dpdk_daq_inject 
 * @purpose: Inject a new packet going either the same or opposite 
 *           direction as specified packet.
 * @params: 
 *          void *handle: Handle context
 *          DAQ_PktHdr_t *hdr: DAQ packet header
 *          len:
 *          reverse: 
 * @return: 
 *          DAQ_SUCCESS: if no error
 *          DAQ_ERROR: if fail.
 */
static int dpdk_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, 
                            const uint8_t *packet_data, uint32_t len, int reverse)
{
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    int i, tx_ring_idx = DAQ_DPDK_PASSIVE_DEV_IDX;
    
    memcpy(context->inj_buffer, context->pkt_buffer, 14); // copy Hdr layer 2 to inj_buffer.
    memcpy(&context->inj_buffer[14], packet_data, len); // copy data packet to inj_buffer.
    len += 14; // update packet len
/*
    if (dpdk_send(context->app.pools[tx_ring_idx], (char *)context->inj_buffer, len , 1) < 0)
    {
        DPE(context->errbuf, "%s", "dpdk_send() error.");
        return DAQ_ERROR;
    }
*/
    context->stats.packets_injected++;
    return DAQ_SUCCESS;
}


/*
 * @dpdk_daq_breadkloop
 * @purpose:
 * @param: void *handle: ptr to context handling.
 * @return: 
 *         DAQ_SUCCESS: no error.
 *         DAQ_ERROR: if failed. 
 */
static int dpdk_daq_breadkloop(void *handle)
{
    Dpdk_Context_t *context = (Dpdk_Context_t *)handle;
    if(!context->app.pools[DAQ_DPDK_PASSIVE_DEV_IDX])
        return DAQ_ERROR;

    context->breakloop = 1;

    return DAQ_SUCCESS;
}

/*
 * @dpdk_daq_stop:
 * @purpose: stop DAQ_DPDK service
 * @params:
 * @retun: DAQ_SUCCESS if no error.
 *          Else, return error message
 */
static int dpdk_daq_stop(void *handle)
{
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    int i;

    update_hw_stats(context);

    for( i = 0; i < kAPPMAXSOCKET; i++) 
    {
        if (context->app.pools[i])
        {
            //dpdk_close(context->app.pools[i]);
            context->app.pools[i] = NULL;
        }
    }
    context->state = DAQ_STATE_STOPPED;

    return DAQ_SUCCESS;
}


/*
 * @dpdk_daq_shutdown
 * @purpose: shutdown dpdk_daq module.
 * @params: 
 *        void *handle: ptr to context handling.
 * @return: 
 */
static void dpdk_daq_shutdown(void *handle)
{
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    int i;

    for (i = 0; i < kAPPMAXSOCKET; i++)
    {
        if (context->app.pools[i])
            rte_pktmbuf_free(context->app.pools[i]);
    }

    if (context->devices[DAQ_DPDK_PASSIVE_DEV_IDX])
        free(context->devices[DAQ_DPDK_PASSIVE_DEV_IDX]);

    //if (context->filter_string)
        //free(context->filter_string);

    free(context);
}

static DAQ_State dpdk_daq_check_status(void *handle) 
{
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    return context->state;
}


/*
 * @dpdk_daq_get_stats
 * @purpose: get collection of statistics
 * @params: 
 *        void *handle : ptr to context
 *        DAQ_Stats_t *stats: ptr to DAQ statistic struct
 * @return: 
 *        DAQ_SUCCESS: if no error
 *        DAQ_ERROR: if failed & exit.
 */
static dpdk_daq_get_stats(void *handle, DAQ_Stats_t *stats) 
{
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    
    update_hw_stats(context);

    memcpy(stats, &context->stats, sizeof(DAQ_Stats_t));
    
    return DAQ_SUCCESS;
}

/*
 * @dpdk_daq_reset_stats
 */
static void dpdk_daq_reset_stats(void *handle)
{
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    struct dpdk_stat ds;
    int i;
/*
    memset(&context->stats, 0 , sizeof(DAQ_Stats_t));
    memset(&ds, 0, sizeof(struct dpdk_stat));

    
    for (i = 0; i < context->num_devices; i++)
    {
        if (context->ring_handles[i] 
                && dpdk_stats(context->ring_handles[i], &ds) == 0)
        {
            context->base_recv[i] = ds.recv;
            context->base_drop[i] = ds.drop;
        }
    }
  */
    printf("Not use righ now\n!");
}

static int dpdk_daq_get_snaplen(void *handle) {
    Dpdk_Context_t *context =(Dpdk_Context_t *) handle;

    if(!context->app.pools[kAPPMAXSOCKET])
        return DAQ_ERROR;
    else
        return context->snaplen;
}

static int dpdk_daq_breakloop(void *handle)
{
  Dpdk_Context_t *context =(Dpdk_Context_t *) handle;

  if(!context->app.pools[kAPPMAXSOCKET])
      return DAQ_ERROR;

  context->breakloop = 1;

  return DAQ_SUCCESS;
}

static uint32_t dpdk_daq_get_capabilities(void *handle) {
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
        DAQ_CAPA_INJECT_RAW | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BPF;
}


static int dpdk_daq_get_datalink_type(void *handle) {
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    if (!context)
        return DAQ_ERROR;
    return DAQ_SUCCESS;
}

static const char *dpdk_daq_get_errbuf(void *handle) {
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    return context->errbuf;
}

static void dpdk_daq_set_errbuf(void *handle, const char *string) {
    Dpdk_Context_t *context = (Dpdk_Context_t *) handle;
    if (!string)
        return;
    DPE(context->errbuf, "%s", string);
}

static int dpdk_daq_get_device_index(void *handle, const char *device) 
{
    return DAQ_ERROR_NOTSUP;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t dpdk_daq_module_data = 
#endif
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_DPDK_VERSION,
    .name = "odp",
    .type = DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    .initialize = dpdk_daq_initialize,
    .set_filter = dpdk_daq_set_filter,
    .start = dpdk_daq_start,
    .acquire = dpdk_daq_acquire,
    .inject = dpdk_daq_inject,
    .breakloop = dpdk_daq_breakloop,
    .stop = dpdk_daq_stop,
    .shutdown = dpdk_daq_shutdown,
    .check_status = dpdk_daq_check_status,
    .get_stats = dpdk_daq_get_stats,
    .reset_stats = dpdk_daq_reset_stats,
    .get_snaplen = dpdk_daq_get_snaplen,
    .get_capabilities = dpdk_daq_get_capabilities,
    .get_datalink_type = dpdk_daq_get_datalink_type,
    .get_errbuf = dpdk_daq_get_errbuf,
    .set_errbuf = dpdk_daq_set_errbuf,
    .get_device_index = dpdk_daq_get_device_index
};

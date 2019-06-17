/*
** Future System version <www.future.co.kr>
**
** DAQ_ODP_DPDK/Snort 
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <stdio.h>

#include <daq_api.h>
#include <sfbpf.h>

#include <odp.h>
#include "dbg.h"


#define DAQ_DPDK_ODP_VERSION 1

/* Size of shared memory block*/
#define SHM_PKT_POOL_SIZE      8192
/*Buffer size of packet pool buffer*/
#define SHM_PKT_POOL_BUF_SIZE  1856
/* Maximum number of packet in a burst*/
#define MAX_PKT_BURST          32

#define DPDK_ODP_MODE_PKT_BURST  0   /* Handle packets in bursts */
#define DPDK_ODP_MODE_PKT_SCHED  1   /* Handle packets in scheduler & queues */

/* 
 * DPDK-ODP Interface struct to handle interfaces
 * interfaces mean port 
 */
typedef struct _odp_interface
{
    struct _odp_interface *next;
    struct _odp_interface *peer;
    odp_pktio_t pktio;
    char *ifname;
    int index;
} ODP_Interface_t;


/*
 * ODP_DPDK main context struct
 */
typedef struct _odp_context
{
    char *device;
    char *filter;
    int snaplen;
    int timeout;   
    uint64_t sched_wait;
    ODP_Interface_t *interfaces;
    odp_pool_t pool;
    int mode;
    bool debug;
    struct sfbpf_program fcode;
    volatile bool break_loop;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
    //odp_barrier_t barrier;
} ODP_Context_t;


/*
 * @stop_dpdk_odp_context
 * @purpose: stop module context
 * @params:
 *      ODP_Context_t *odpc : DPDK_ODP context
 * @return:
 */
static void stop_dpdk_odp_context(ODP_Context_t *odpc)
{
    ODP_Interface_t *intf;
    odp_queue_t queue;

    for (intf = odpc->interfaces; intf; intf = intf->next)
    {
        if (intf->pktio != ODP_PKTIO_INVALID)
        {
            if ((queue = odp_pktio_inq_getdef(intf->pktio)) != ODP_QUEUE_INVALID)
            {
                odp_pktio_inq_remdef(intf->pktio);
                odp_queue_destroy(queue);
            }
            odp_pktio_close(intf->pktio);
            intf->pktio = ODP_PKTIO_INVALID;
        }
    }
    if (odpc->pool != ODP_POOL_INVALID)
    {
        odp_pool_destroy(odpc->pool);
        odpc->pool = ODP_POOL_INVALID;
    }
}

/*
 * @destroy_dpdk_odp_daq_context
 * @purpose: destroy context 
 * @params:
 *      ODP_Context_t *odpc: DPDK_ODP context
 * @return: 
 */
static void destroy_dpdk_odp_daq_context(ODP_Context_t *odpc)
{
    ODP_Interface_t *intf;

    if (odpc)
    {
        while ((intf = odpc->interfaces) != NULL)
        {
            odpc->interfaces = intf->next;
            free(intf->ifname);
            free(intf);
        }
        free(odpc->device);
        free(odpc->filter);
        sfbpf_freecode(&odpc->fcode);
        free(odpc);
    }
}

/*
 *  @daq_initialize: Initialize DPDK-ODP DAQ context 
 *                   (objects, I/O devices, ...) and DAQ Dict
 *  @params:
 *          const DAQ_Config_t *config  : ptr to DAQ config.
 *          void **ctx_ptr              : ptr to context.
 *          char **errbuf               : buffer to handle error case.
 *          size_t len                  : size of errbuf.
 *  @return:    
 *          DAQ_SUCCESS     : No error.
 *          DAQ_ERROR       : Failed
 */
static int dpdk_odp_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    ODP_Context_t *odpc;
    ODP_Interface_t *intf;
    DAQ_Dict *entry;
    char *dev;
    size_t len;
    int num_intfs = 0, rval;

    odpc = calloc(1, sizeof(ODP_Context_t));
    if (!odpc)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new ODP context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    odpc->device = strdup(config->name);
    if (!odpc->device)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    odpc->snaplen = SHM_PKT_POOL_BUF_SIZE;
    odpc->timeout = config->timeout;    /* Cannot convert with odp_schedule_wait_time() until ODP has been init'd. */
    odpc->pool = ODP_POOL_INVALID;

    /* Default configuration options */
    odpc->mode = DPDK_ODP_MODE_PKT_SCHED;

    dev = odpc->device;
    while (*dev != '\0')
    {
        len = strcspn(dev, ",");
        if (len >= IFNAMSIZ)
        {
            snprintf(errbuf, errlen, "%s: Interface name too long! (%zu)", __FUNCTION__, len);
            rval = DAQ_ERROR_INVAL;
            goto err;
        }
        if (len != 0)
        {
            num_intfs++;
            intf = calloc(1, sizeof(ODP_Interface_t));
            if (!intf)
            {
                snprintf(errbuf, errlen, "%s: Couldn't allocate memory for an interface structure!", __FUNCTION__);
                rval = DAQ_ERROR_NOMEM;
                goto err;
            }
            intf->ifname = strndup(dev, len);
            if (!intf->ifname)
            {
                free(intf);
                snprintf(errbuf, errlen, "%s: Couldn't allocate memory for an interface name!", __FUNCTION__);
                rval = DAQ_ERROR_NOMEM;
                goto err;
            }
            intf->pktio = ODP_PKTIO_INVALID;
            intf->index = num_intfs;
            intf->next = odpc->interfaces;
            odpc->interfaces = intf;
            if (config->mode != DAQ_MODE_PASSIVE && num_intfs % 2 == 0)
            {
                odpc->interfaces->peer = odpc->interfaces->next;
                odpc->interfaces->next->peer = odpc->interfaces;
            }
        }
        else
            len += 1;
        dev += len;
    }

    if (!odpc->interfaces || (config->mode != DAQ_MODE_PASSIVE && num_intfs % 2 != 0))
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!", __FUNCTION__, odpc->device);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

    for (entry = config->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, "debug"))
            odpc->debug = true;
        else if (!strcmp(entry->key, "mode"))
        {
            if (!entry->value)
            {
                snprintf(errbuf, errlen, "%s: %s requires an argument!", __FUNCTION__, entry->key);
                rval = DAQ_ERROR_INVAL;
                goto err;
            }
            if (!strcmp(entry->value, "burst"))
                odpc->mode = DPDK_ODP_MODE_PKT_BURST;
            else if (!strcmp(entry->value, "scheduled"))
                odpc->mode = DPDK_ODP_MODE_PKT_SCHED;
            else
            {
                snprintf(errbuf, errlen, "%s: Unrecognized argument for %s: '%s'!", __FUNCTION__, entry->key, entry->value);
                rval = DAQ_ERROR_INVAL;
                goto err;
            }
        }
    }

    odpc->state = DAQ_STATE_INITIALIZED;

    *ctxt_ptr = odpc;
    return DAQ_SUCCESS;

err:
    destroy_dpdk_odp_daq_context(odpc);

    return rval;
}

/*
 * @daq_set_filter
 * @purpose: set the module's BPF based on given string
 *
 * @params:
 *      void *handle: context handling ptr.
 *      const char *filter: given string.
 * 
 * @return:
 *      DAQ_SUCCESS: no error
 *      DAQ_ERROR: failed.
 */
static int dpdk_odp_daq_set_filter(void *handle, const char *filter)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;
    struct sfbpf_program fcode;

    if (odpc->filter)
        free(odpc->filter);

    odpc->filter = strdup(filter);
    if (!odpc->filter)
    {
        DPE(odpc->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(odpc->snaplen, DLT_EN10MB, &fcode, odpc->filter, 1, 0) < 0)
    {
        DPE(odpc->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&odpc->fcode);
    odpc->fcode.bf_len = fcode.bf_len;
    odpc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

/*
 * @daq_start
 * @purpose: start pkts capture ( starting context, device opening, 
 *          dpdk environment init, memory allocation, ...)
 * @params: 
 *          void *handle: ptr to handle context.
 *  @return:
 */
static int dpdk_odp_daq_start(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;
    ODP_Interface_t *intf;
    odp_queue_param_t qparam;
    odp_queue_t inq_def;
    odp_pool_param_t params;
    char inq_name[ODP_QUEUE_NAME_LEN];
    int rval = DAQ_ERROR;
    //odp_barrier_t barrier;

    /* Init DPDK_ODP before calling anything else */
    if (odp_init_global(NULL, NULL))
    {
        DPE(odpc->errbuf, "Error: ODP global init failed.");
        goto err;
    }

    /* Init this thread */
    if (odp_init_local(ODP_THREAD_WORKER))
    {
        DPE(odpc->errbuf, "Error: ODP local init failed.");
        goto err;
    }

    /* Calculate the scheduler timeout period. */
    odpc->sched_wait = (odpc->timeout > 0) ? odp_schedule_wait_time(odpc->timeout * 1000000) : ODP_SCHED_WAIT;

    //odpc->sched_wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS * 100);

    /* Create packet pool */
    memset(&params, 0, sizeof(params));
    params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
    params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
    params.pkt.num     = SHM_PKT_POOL_SIZE;
    params.type        = ODP_POOL_PACKET;

    odpc->pool = odp_pool_create("packet_pool", &params);
    if (odpc->pool == ODP_POOL_INVALID)
    {
        DPE(odpc->errbuf, "Error: packet pool create failed.");
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }
    
    if (odpc->debug)
        odp_pool_print(odpc->pool);

    /* Create a pktio and scheduled input queue for each interface. */
    for (intf = odpc->interfaces; intf; intf = intf->next)
    {
        odp_pktio_param_t pktio_param;
        odp_pktio_param_init(&pktio_param);
        memset(&pktio_param, 0, sizeof(pktio_param));
        if (odpc->mode == DPDK_ODP_MODE_PKT_BURST)
            pktio_param.in_mode = ODP_PKTIN_MODE_RECV; 
        else if (odpc->mode == DPDK_ODP_MODE_PKT_SCHED)
             pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

        intf->pktio = odp_pktio_open(intf->ifname, odpc->pool, &pktio_param);
        if (intf->pktio == ODP_PKTIO_INVALID)
        {
            DPE(odpc->errbuf, "Error: pktio create failed for %s", intf->ifname);
            rval = DAQ_ERROR_NODEV;
            goto err;
        }

        if (odpc->mode == DPDK_ODP_MODE_PKT_SCHED)
        {
            odp_queue_param_init(&qparam);
            qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
            qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
            qparam.sched.group = ODP_SCHED_GROUP_ALL;
            qparam.context = intf;
            snprintf(inq_name, sizeof(inq_name), "%" PRIu64 "-pktio_inq_def", odp_pktio_to_u64(intf->pktio));
            //inq_name[ODP_QUEUE_NAME_LEN -1] = '\0';
            log_info("Creating queue ...");
            inq_def = odp_queue_create(inq_name, ODP_QUEUE_TYPE_PKTIN, &qparam);
            if (inq_def == ODP_QUEUE_INVALID)
            {
                DPE(odpc->errbuf, "Error: pktio queue creation failed");
                rval = DAQ_ERROR;
                goto err;
            }

            if (odp_pktio_inq_setdef(intf->pktio, inq_def))
            {
                DPE(odpc->errbuf, "Error: default input-Q setup");
                rval = DAQ_ERROR;
                goto err;
            }
        }
       
        /* start pktio for each interface */
        rval = odp_pktio_start(intf->pktio);
        if (rval) {
            DPE(odpc->errbuf, "Error: unable to start %s", intf->ifname);
            goto err;
        }
    }

    //odp_barrier_init(&(odpc->barrier),1);
    odpc->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;

err:
    return rval;
}

/* 
 * re-define DAQ_VER_DICT translation table
 *
 */
static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS        /* DAQ_VERDICT_IGNORE */
};

/*
 *  @drop_err_pkts
 *  @purpose: drop packets when error be detected.
 *  @params:
 *          pkt_tbl[] : packet table
 *          len : length of table
 *  @return:
 *         pkt_cnt: packet counts.
 */
static int dpdk_drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len)
{
    odp_packet_t pkt;
    unsigned pkt_cnt = len;
    unsigned i, j;

    for (i = 0, j = 0; i < len; i++)
    {
        pkt = pkt_tbl[i];
        if (odp_unlikely(odp_packet_has_error(pkt))) {
            odp_packet_free(pkt);
            pkt_cnt--;
        } else if (odp_unlikely( i != j++)) {
            pkt_tbl[j - 1] = pkt;
        }
    }

    return pkt_cnt;
}


/*
 * @daq_acquire_burst
 * @purpose: acquiring packets by instance directly (burst) 
 * @params: 
 * @return: 
 *          0
 */
static int dpdk_odp_daq_acquire_burst(ODP_Context_t *odpc, int cnt, DAQ_Analysis_Func_t callback, void *user)
{
    struct timeval tv;
    ODP_Interface_t *intf;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    odp_packet_t pkt_tbl_recv[MAX_PKT_BURST], pkt_tbl_send[MAX_PKT_BURST];
    odp_packet_t pkt;
    const uint8_t *data;
    uint16_t len;
    int pkts_recv, pkts_send, pkt_burst;
    int i, c = 0;

    while (c < cnt || cnt <= 0)
    {
        for (intf = odpc->interfaces; intf; intf = intf->next)
        {
            /* Has breakloop() been called? */
            if (odpc->break_loop)
            {
                odpc->break_loop = false;
                return 0;
            }

            pkt_burst = MAX_PKT_BURST;
            if (cnt > 0)
            {
                if (c > cnt)
                    break;
                if (cnt - c < MAX_PKT_BURST)
                    pkt_burst = cnt - c;
            }

            //odp_barrier_wait(&(odpc->barrier));
            pkts_recv = odp_pktio_recv(intf->pktio, pkt_tbl_recv, pkt_burst);
            if (pkts_recv < 0)
                return DAQ_ERROR;
            if (pkts_recv == 0)
                continue;

            odpc->stats.hw_packets_received += pkts_recv;

            int pkts_ok = dpdk_drop_err_pkts(pkt_tbl_recv, pkts_recv);
            
            /* Use a single timestamp for all packets received in a burst. */
            gettimeofday(&tv, NULL);

            /* Process each packet received, adding packets to send to the output
                table and freeing the rest. */
            pkts_send = 0;
            for (i = 0; i < pkts_ok; i++)
            {
                pkt = pkt_tbl_recv[i];
                data = odp_packet_data(pkt);

                verdict = DAQ_VERDICT_PASS;
                len = odp_packet_len(pkt);
                if (!odpc->fcode.bf_insns || sfbpf_filter(odpc->fcode.bf_insns, data, len, len) != 0)
                {
                    daqhdr.ts = tv;
                    daqhdr.caplen = len;
                    daqhdr.pktlen = len;
                    daqhdr.ingress_index = intf->index;
                    daqhdr.egress_index = intf->peer ? intf->peer->index : DAQ_PKTHDR_UNKNOWN;
                    daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
                    daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
                    daqhdr.flags = 0;
                    daqhdr.opaque = 0;
                    daqhdr.priv_ptr = NULL;
                    daqhdr.address_space_id = 0;

                    if (callback)
                    {
                        verdict = callback(user, &daqhdr, data);
                        if (verdict >= MAX_DAQ_VERDICT)
                            verdict = DAQ_VERDICT_PASS;
                        odpc->stats.verdicts[verdict]++;
                        verdict = verdict_translation_table[verdict];
                    }
                    odpc->stats.packets_received++;
                    c++;
                }
                else
                    odpc->stats.packets_filtered++;

                if (intf->peer && verdict == DAQ_VERDICT_PASS)
                {
                    pkt_tbl_send[pkts_send] = pkt;
                    pkts_send++;
                }
                else
                    odp_packet_free(pkt);
            }

            /* sending pkts to output and free memory */
            int sent;
            if (intf->peer && pkts_send > 0) {
                sent = odp_pktio_send(intf->peer->pktio, pkt_tbl_send, pkts_send);
                
                sent = sent > 0? sent : 0;
                if (odp_unlikely(sent < pkts_send)) {
                    do
                        odp_packet_free(pkt_tbl_send[sent]);
                    while (++sent < pkts_send);
                }
                
            }
        }
    }
    return 0;
}

/*
 *  @daq_acquire_scheduled
 *  @purpose: acquiring packets by scheduler & queues.
 *  @params:
 *          ODP_Context_t *odpc: context ptr 
 *          DAQ_Analysis_Funct_t callback : call back from DAQ analysis function.
 *          void *user: user ptr
 *  @return: 0
 */
static int dpdk_odp_daq_acquire_scheduled(ODP_Context_t *odpc, int cnt, DAQ_Analysis_Func_t callback, void *user)
{
    struct timeval tv;
    ODP_Interface_t *intf;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    odp_event_t ev_tbl_recv[MAX_PKT_BURST];
    odp_packet_t pkt_send_tbl[MAX_PKT_BURST];
    odp_packet_t pkt;
    odp_event_t ev;
    //odp_queue_t outq_def;
    const uint8_t *data;
    uint16_t len;
    int ev_recv, pkt_burst;
    int i, c = 0;

    while (c < cnt || cnt <= 0)
    {
        /* Has breakloop() been called? */
        if (odpc->break_loop)
        {
            odpc->break_loop = false;
            return 0;
        }

        pkt_burst = MAX_PKT_BURST;
        if (cnt > 0)
        {
            if (c > cnt)
                break;
            if (cnt - c < MAX_PKT_BURST)
                pkt_burst = cnt - c;
        }

        ev_recv = odp_schedule_multi(NULL, odpc->sched_wait, ev_tbl_recv, pkt_burst);
        if (ev_recv < 0)
            return DAQ_ERROR;
        if (ev_recv == 0)
            return 0;

        odpc->stats.hw_packets_received += ev_recv;
        
        /* Use a single timestamp for all packets received in a burst. */
        gettimeofday(&tv, NULL);

        /* Process each packet received, queuing packets to send to the associated
            output queue and freeing the rest. */
        int send = 0;
        for (i = 0; i < ev_recv; i++)
        {
            ev = ev_tbl_recv[i];
            if (odp_event_type(ev) != ODP_EVENT_PACKET)
            {
                printf("Received unexpected ODP event type (%d)!\n", odp_event_type(ev));
                odp_buffer_free(odp_buffer_from_event(ev));
                continue;
            }

            pkt = odp_packet_from_event(ev);
            data = odp_packet_data(pkt);
            len = odp_packet_len(pkt);

            /* Chain event => packet => pktio => default input queue => context
                to find the interface structure associated with the ingress
                interface of this packet.  This is kind of ridiculous. */
            intf = (ODP_Interface_t *) odp_queue_context(odp_pktio_inq_getdef(odp_packet_input(pkt)));
            verdict = DAQ_VERDICT_PASS;
            if (!odpc->fcode.bf_insns || sfbpf_filter(odpc->fcode.bf_insns, data, len, len) != 0)
            {
                daqhdr.ts = tv;
                daqhdr.caplen = len;
                daqhdr.pktlen = len;
                daqhdr.ingress_index = intf->index;
                daqhdr.egress_index = intf->peer ? intf->peer->index : DAQ_PKTHDR_UNKNOWN;
                daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
                daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
                daqhdr.flags = 0;
                daqhdr.opaque = 0;
                daqhdr.priv_ptr = NULL;
                daqhdr.address_space_id = 0;

                if (callback)
                {
                    verdict = callback(user, &daqhdr, data);
                    if (verdict >= MAX_DAQ_VERDICT)
                        verdict = DAQ_VERDICT_PASS;
                    odpc->stats.verdicts[verdict]++;
                    verdict = verdict_translation_table[verdict];
                }
                odpc->stats.packets_received++;
                c++;
            }
            else
                odpc->stats.packets_filtered++;
            /*
            if (odp_unlikely(dpdk_drop_err_pkts(&pkt, 1) == 0)) {
                log_info("pkt[%d] has error!",i);
                continue;
            }*/

            if (intf->peer && verdict == DAQ_VERDICT_PASS)
            {
                pkt_send_tbl[send] = pkt;
                send++;
                /* Enqueue the packet for output */
                /*outq_def = odp_pktio_outq_getdef(intf->peer->pktio);
                if (odp_queue_enq(outq_def, ev)) {
                    log_info("Queue enqueue failed.");
                    odp_packet_free(pkt);
                    continue;
                } */

               //odp_pktio_send(intf->peer->pktio, &pkt, 1);
            } else
                odp_packet_free(pkt);
        }

        int ret, tx_drop;
        //for (intf = odpc->interfaces;intf; intf= intf->next) { 
            //odp_pktio_send(intf->peer->pktio, pkt_send_tbl, send);
            /*ret = odp_pktio_start(intf->peer->pktio);
            if (ret) { 
                log_info("ERROR: unable to start interfaces!");
            }*/
        
            ret = odp_pktio_send(intf->peer->pktio, pkt_send_tbl, send);
            
            ret = odp_unlikely(ret < 0) ? 0 : ret;
            tx_drop = send - ret;
            if (odp_unlikely(tx_drop)) {
                for ( int j = ret; j < send; j++)
                    odp_packet_free(pkt_send_tbl[j]);
            }
        //}
    }

    return 0;
}

/*
 * @daq_acquire
 * @purpose: Acquire up to <cnt> packets and call <callback> for each with 
 *           <user> as the final argurment.
 * @params:
 *        handle : ptr to context handling.
 *        cnt    : couting packets
 *        callback : To get callback to analysis function
 *        metaback:
 *        user 
 *  @return:
 *      daq_acquire_burst: use mode PKT_BURST
 *      daq_acquire_scheduled : use mode PKT_SCHED
 */
static int dpdk_odp_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    if (odpc->mode == DPDK_ODP_MODE_PKT_SCHED)
        return dpdk_odp_daq_acquire_scheduled(odpc, cnt, callback, user);

    return dpdk_odp_daq_acquire_burst(odpc, cnt, callback, user);
}

/*
 * @daq_inject
 * @purpose: Inject a new packet going either the same or opposite direction 
 *           as specified packet.
 * @params:
 *          void *handle: handling context ptr.
 *          DAQ_PktHdr_t *hdr: DAQ packet header
 *          len: 
 *          reverse:
 * @return:
 *          DAQ_SUCCESS: no error
 *          DAQ_ERROR: failed.
 */
static int dpdk_odp_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;
    ODP_Interface_t *intf;
    odp_packet_t pkt;

    for (intf = odpc->interfaces; intf && intf->index != hdr->ingress_index; intf = intf->next);
    if (!intf || (!reverse && !(intf = intf->peer)))
        return DAQ_ERROR;

    pkt = odp_packet_alloc(odpc->pool, len);
    if (!pkt)
        return DAQ_ERROR_NOMEM;

    if (odp_packet_copydata_in(pkt, 0, len, packet_data) < 0)
    {
        odp_packet_free(pkt);
        return DAQ_ERROR;
    }

    if (odpc->mode == DPDK_ODP_MODE_PKT_SCHED)
    {
        if (odp_queue_enq(odp_pktio_outq_getdef(intf->pktio), odp_packet_to_event(pkt)) < 0)
        {
            odp_packet_free(pkt);
            return DAQ_ERROR;
        }
    }
    else if (odp_pktio_send(intf->pktio, &pkt, 1) != 1)
    {
        odp_packet_free(pkt);
        return DAQ_ERROR;
    }

    odpc->stats.packets_injected++;

    return DAQ_SUCCESS;
}

/*
 * @daq_breakloop
 * @purpose: breaking out of the acquisition loop after 
 *           the current iteration.
 * @params: 
 *      void *handle: ptr to context handling.
 * @return:
 *      DAQ_SUCCESS: no error
 *      DAQ_ERROR: if failed.
 */
static int dpdk_odp_daq_breakloop(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    odpc->break_loop = true;

    return DAQ_SUCCESS;
}

/*
 * @daq_stop
 * @purpose: stop daq dpdk-odp queuing packets, if possible.
 * @params: 
 *          context handling ptr
 * @return: 
 *      DAQ_SUCCESS: no error
 */
static int dpdk_odp_daq_stop(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    stop_dpdk_odp_context(odpc);

    odpc->state = DAQ_STATE_STOPPED;

    return DAQ_SUCCESS;
}


/*
 * @daq_shutdown
 * @purpose: close the device and clean up.
 *
 * @params:
 *      void *handle: context handling ptr
 * @return: 
 */
static void dpdk_odp_daq_shutdown(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    stop_dpdk_odp_context(odpc);
    destroy_dpdk_odp_daq_context(odpc);

    if (odp_term_local() == 0)
        odp_term_global();
}

/*
 * @daq_check_status
 * @purpose: check the status of the module
 * @params:
 *      void *hanle: context handling ptr
 * @return:
 *      context state
 */
static DAQ_State dpdk_odp_daq_check_status(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    return odpc->state;
}


/*
 * @daq_get_stats
 * @purpose: populate the <stats> structure with 
 *           the current DAQ stats.
 * @params:
 *      void *hanle: context handling ptr
 *      DAQ_Stats_t *stats: daq stats ptr
 * @return: 
 *      DAQ_SUCCESS: no error.
 */
static int dpdk_odp_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    memcpy(stats, &odpc->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

/*
 * @daq_reset_stats
 * @purpose: reset internal stats of the DAQ's module.
 * @params:
 *      void *handle: context handling ptr
 * @return:
 */
static void dpdk_odp_daq_reset_stats(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    memset(&odpc->stats, 0, sizeof(DAQ_Stats_t));
}

/* 
 * @daq_get_snaplen:
 * @purpose: get the configured snaplen. 
 * @params:
 *      void *handle: context handling ptr
 * @return:
 *      context->snaplen.
 */
static int dpdk_odp_daq_get_snaplen(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    return odpc->snaplen;
}

/*
 * @daq_get_capabilities
 * @purpose: return a bitfield of the devices's capabilities
 *
 * @params:
 *      void *handle: context handling ptr
 * @return:
 */
static uint32_t dpdk_odp_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT 
        | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF | DAQ_CAPA_DEVICE_INDEX;
}

/* @daq_get_datalink_type
 * @purpose: get the instance's datalink type.
 * @params:
 *      void *handle: context handling ptr
 * @return:
 *      DLT_EN10MB (ETHERNET 10Mb, 100Mb, 1000 Mb and up)
 */
static int dpdk_odp_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

/*
 * @daq_get_errbuf:
 * @purpose: get pointer to the module instance's internal  error buffer.
 *
 * @params:
 *      void *handle: context handling ptr
 * @return:
 *      context->errbuf
 */
static const char *dpdk_odp_daq_get_errbuf(void *handle)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    return odpc->errbuf;
}

/* 
 * @daq_set_errbuf:
 * @purpose: Write a string to the module instance's internal error buffer.
 * @params:
 *      void *handle: context handling ptr
 *      const char *string: given string
 * @return:
 */
static void dpdk_odp_daq_set_errbuf(void *handle, const char *string)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;

    if (!string)
        return;

    DPE(odpc->errbuf, "%s", string);
    return;
}

/*
 * @daq_get_device_index:
 * @purpose: get the index of the given named device if possible.
 *
 * @params:
 *      void *handle: context handling ptr
 *      const char *device: given deive's name.
 * @return:
 *      device's index
 */
static int dpdk_odp_daq_get_device_index(void *handle, const char *device)
{
    ODP_Context_t *odpc = (ODP_Context_t *) handle;
    ODP_Interface_t *intf;

    for (intf = odpc->interfaces; intf; intf = intf->next)
    {
        if (!strcmp(device, intf->ifname))
            return intf->index;
    }

    return DAQ_ERROR_NODEV;
}

/*
 * @daq_module_data:
 * @purpose: main module data definition.
 * @params:
 * @return:
 */
#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t afpacket_daq_module_data =
#endif
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_DPDK_ODP_VERSION,
    .name = "dpdkodp",
    .type = DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE,
    .initialize = dpdk_odp_daq_initialize,
    .set_filter = dpdk_odp_daq_set_filter,
    .start = dpdk_odp_daq_start,
    .acquire = dpdk_odp_daq_acquire,
    .inject = dpdk_odp_daq_inject,
    .breakloop = dpdk_odp_daq_breakloop,
    .stop = dpdk_odp_daq_stop,
    .shutdown = dpdk_odp_daq_shutdown,
    .check_status = dpdk_odp_daq_check_status,
    .get_stats = dpdk_odp_daq_get_stats,
    .reset_stats = dpdk_odp_daq_reset_stats,
    .get_snaplen = dpdk_odp_daq_get_snaplen,
    .get_capabilities = dpdk_odp_daq_get_capabilities,
    .get_datalink_type = dpdk_odp_daq_get_datalink_type,
    .get_errbuf = dpdk_odp_daq_get_errbuf,
    .set_errbuf = dpdk_odp_daq_set_errbuf,
    .get_device_index = dpdk_odp_daq_get_device_index,
    .modify_flow = NULL,
    .hup_prep = NULL,
    .hup_apply = NULL,
    .hup_post = NULL,
};

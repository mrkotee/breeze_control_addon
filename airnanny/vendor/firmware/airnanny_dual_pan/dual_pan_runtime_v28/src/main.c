/* Single-boot narrow V4/V7 commissioning transport. Host-only crypto. */
#include "gate_events.h"
#include "dual_sched.h"
#include "dual_records.h"
#include "ack_trace.h"
#include "submission_trace.h"
volatile ack_trace_t ack_trace;
volatile submission_trace_t submission_trace;
#include "management.h"
#ifdef ASSOC_HOST_TEST
#include "assoc_main_mock.h"
#else
#include "nrf.h"
#include "sdk_config.h"
#include "nrf_802154.h"
#include "nrf_802154_core.h"
#include "platform/random/nrf_802154_random.h"
#include "app_usbd.h"
#include "app_usbd_cdc_acm.h"
#include "app_usbd_serial_num.h"
#include "nrf_drv_clock.h"
#include "app_error.h"
#endif
#include <stdio.h>
#include <string.h>
static void cdc_event(app_usbd_class_inst_t const *,app_usbd_cdc_acm_user_event_t);
APP_USBD_CDC_ACM_GLOBAL_DEF(cdc,cdc_event,0,1,NRF_DRV_USBD_EPIN2,NRF_DRV_USBD_EPIN1,NRF_DRV_USBD_EPOUT1,APP_USBD_CDC_COMM_PROTOCOL_AT_V250);
static char input[ASSOC_COMMAND_MAX],pending_command[ASSOC_COMMAND_MAX],boot[33],line[ASSOC_LINE_MAX];
static char output[32][ASSOC_LINE_MAX];static uint32_t oh,ot,out_drop,last_id;
static uint8_t byte;static size_t input_length;
static bool open,busy,discard,command_pending,has_id,line_error,command_overflow;
static bool rx_cutoff_stalled;
/* Two independent sessions. One radio means one in-flight frame, so there is
 * still a single tx_t; it now records which session owns it. */
static commission_t sessions[DUAL_CONTEXTS];
static unsigned poll_turn;            /* round robin for automatic polls */
static uint32_t config_generation;    /* published to the gate and the records */
static uint32_t starved_polls;        /* a context ready to poll but not served */
static unsigned last_ctx;             /* the context a command last acted on */

static bool immediate_ack;
/* The driver's auto-ACK enable is global, so it is on whenever any context may
 * answer. Which context actually answers is decided per frame by the admission
 * layer, from that context's own gate. V25 could only gate the whole radio,
 * which in a dual runtime would silence both contexts whenever either scanned. */
static void set_ack(bool value){immediate_ack=value;nrf_802154_auto_ack_set(value);}
static void radio_service(void)
{
    bool any=false;
    for(unsigned c=0;c<DUAL_CONTEXTS;c++){
        bool live=open && sessions[c].phase==G_MANAGEMENT;
        bool scanning=sessions[c].recovery.phase==R_SCANNING;
        dual_binding_scanning(c,scanning);
        dual_binding_ack(c,live && !scanning);
        any=any || (live && !scanning);
    }
    set_ack(any);
}
typedef struct {uint8_t raw[128];uint32_t id,session,start_us,end_us,rf_start_us;unsigned kind,ctx;bool automatic,ack_present;uint8_t ack_fcf,ack_dsn;volatile uint8_t state;assoc_tx_result_t result;unsigned abort_reason,cleanup;uint32_t abort_started_us;bool submitted,callback_seen,terminal,output_queued,abort_attempted,abort_accepted,pre_air_cca;uint32_t cca_due_us;uint8_t cca_attempts,cca_busy,cca_be;uint32_t rx_admission_deferrals;bool cca_initialized;uint8_t mac_retries;uint32_t intent_us;} tx_t;
static tx_t tx;
static commission_t *owner(void){return &sessions[tx.ctx<DUAL_CONTEXTS?tx.ctx:0];}
static bool tx_terminal_request(unsigned reason);
static uint32_t irq_lock(void){uint32_t p=__get_PRIMASK();__disable_irq();return p;}
static void irq_unlock(uint32_t p){__DMB();__set_PRIMASK(p);}
/* Handoff excludes USB priority6, while RADIO priority0 remains available.
 * Driver's own radio critical section is unchanged; no added global IRQ mask. */
static uint32_t handoff_lock(void){
#ifdef ASSOC_HOST_TEST
 return 0;
#else
#if NRFX_USBD_CONFIG_IRQ_PRIORITY != 6 || USBD_CONFIG_IRQ_PRIORITY != 6
#error Re-audit handoff fence for changed USB priority
#endif
 uint32_t b=__get_BASEPRI();__set_BASEPRI_MAX(6u<<(8u-__NVIC_PRIO_BITS));__DSB();__ISB();return b;
#endif
}
static void handoff_unlock(uint32_t b){
#ifdef ASSOC_HOST_TEST
 (void)b;
#else
 __DMB();__set_BASEPRI(b);__ISB();
#endif
}
/* A fault in the shared evidence path (USB, the output queue, the RX ring, the
 * clock) invalidates both contexts, because neither one's state can still be
 * trusted. A fault belonging to one context stops only that context: the issue
 * requires that a failure in one must not corrupt the other. */
static void stop_all_loss(void)
{
    tx_terminal_request(4);
    uint32_t p=irq_lock();
    for(unsigned c=0;c<DUAL_CONTEXTS;c++)commission_stop(&sessions[c]);
    irq_unlock(p);
    set_ack(false);
}
static void stop_ctx_loss(unsigned ctx)
{
    if(ctx>=DUAL_CONTEXTS){stop_all_loss();return;}
    if(tx.state&&tx.ctx==ctx)tx_terminal_request(4);
    uint32_t p=irq_lock();commission_stop(&sessions[ctx]);irq_unlock(p);
}
static bool emit(void)
{
    if(oh-ot==32){if(out_drop!=UINT32_MAX)out_drop++;stop_all_loss();return false;}
    memcpy(output[oh%32],line,strlen(line)+1);oh++;return true;
}
static void hex_le(const uint8_t *a,size_t n,char *out,bool canonical)
{static const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){uint8_t v=a[canonical?n-1-i:i];out[2*i]=h[v>>4];out[2*i+1]=h[v&15];}out[2*n]=0;}
#include "cca_backoff.inc"
#include "tx_lifecycle.inc"
static void random_boot(void)
{
    uint8_t a[16];NRF_RNG->CONFIG=1;NRF_RNG->TASKS_START=1;
    for(unsigned i=0;i<16;i++){unsigned budget=1000000;while(!NRF_RNG->EVENTS_VALRDY && --budget){}if(!budget)APP_ERROR_HANDLER(NRF_ERROR_TIMEOUT);a[i]=(uint8_t)NRF_RNG->VALUE;NRF_RNG->EVENTS_VALRDY=0;}
    NRF_RNG->TASKS_STOP=1;hex_le(a,16,boot,false);
}
/* Bound means this context was actually resumed, which management_resume marks
 * by giving it a session number. Phase is the wrong test: stopping the runtime
 * leaves a never-resumed context in G_STOPPED, which would then look bound and
 * could answer a STATUS with a session number it never had. */
static bool is_bound(unsigned c){return sessions[c].association.session!=0;}
/* Which context a STATUS that named none should describe: the one bound context
 * when exactly one is, otherwise the context a command last acted on. The
 * second case is what makes a rejected bind observable: nothing is bound after
 * it, yet the fault belongs to the context the command named, and a STATUS that
 * silently described the other one would hide it. An action still never
 * defaults; this is only for a read-only record, which names the context it
 * describes. */
static unsigned lowest_bound(void)
{
    for(unsigned c=0;c<DUAL_CONTEXTS;c++)if(is_bound(c))return c;
    return last_ctx<DUAL_CONTEXTS?last_ctx:0;
}
static unsigned bound_count(void)
{
    unsigned k=0;for(unsigned c=0;c<DUAL_CONTEXTS;c++)if(is_bound(c))k++;return k;
}
static void status(uint32_t id,unsigned ctx)
{
    if(ctx>=DUAL_CONTEXTS)ctx=lowest_bound();
    commission_t *s=&sessions[ctx];
    gate_crc_t crc=gate_hw_crc_snapshot();
    snprintf(line,sizeof(line),RADIO_PREFIX " STATUS boot=%s id=%lu ctx=%u session=%lu state=%s association_state=%s key_state=%s generation=%lu assigned_short=%04x polls=%lu pending=%u used=%u immediate_ack=%u application_tx=typed_fan_once rx_revision=%lu rx_drop=%lu out_drop=%lu crc_error=%lu recovery=%s time_us=%lu tx_end_us=%lu deadline_us=%lu beacon_revision=%lu response_revision=%lu tx_owner=%s rf_started=%u callback_seen=%u completion_output_queued=%u watchdog_fired=%u cleanup=%u quarantine=%u reboot_required=%u accepted_count=%lu terminal_count=%lu late_callbacks=%lu abort_calls=%lu driver_phase=%s tx_id=%lu queued_us=%lu rf_start_us=%lu callback_us=%lu abort_start_us=%lu tx_result=%s cca_preair=%u cca_attempts=%u cca_busy=%u cca_be=%u cca_due_us=%lu cca_acquisition_limit_us=40000 crc_first_us=%lu crc_last_us=%lu rx_cutoff_grace_us=2000 rx_cutoff_stalled=%u\n",boot,(unsigned long)id,ctx,(unsigned long)s->association.session,commission_name(s->phase),assoc_state_name(s->association.state),key_name(s->keys.state),(unsigned long)s->generation,s->association.result.short_address,(unsigned long)s->keys.polls,tx.state!=0,s->keys.used,immediate_ack,(unsigned long)gate_hw_revision(),(unsigned long)gate_hw_dropped(),(unsigned long)out_drop,(unsigned long)crc.count,recovery_name(s->recovery.phase),(unsigned long)gate_hw_now_us(),(unsigned long)s->recovery.tx_end_us,(unsigned long)s->recovery.deadline_us,(unsigned long)s->recovery.beacon_revision,(unsigned long)s->recovery.response_revision,owner_name(tx.state),tx.rf_start_us!=0,tx.callback_seen,tx.output_queued,tx.abort_reason==ABORT_WATCHDOG,tx.cleanup,tx.state==OWNER_QUARANTINED,reboot_required,(unsigned long)accepted_count,(unsigned long)terminal_count,(unsigned long)late_callbacks,(unsigned long)abort_calls,driver_phase(),(unsigned long)tx.id,(unsigned long)tx.start_us,(unsigned long)tx.rf_start_us,(unsigned long)(tx.callback_seen?tx.end_us:0),(unsigned long)tx.abort_started_us,tx.abort_reason?abort_name(tx.abort_reason):assoc_tx_name(tx.result),tx.pre_air_cca,tx.cca_attempts,tx.cca_busy,tx.cca_be,(unsigned long)tx.cca_due_us,(unsigned long)crc.first_us,(unsigned long)crc.last_us,rx_cutoff_stalled);emit();
}
static bool radio_power_configure(void){nrf_802154_tx_power_set(8);return nrf_802154_tx_power_get()==8;}
/* Resolves which context a command acts on. An explicit ctx always wins. With
 * exactly one context bound, a command that omitted ctx means that one. With
 * more than one bound it is genuinely ambiguous and is refused: guessing is the
 * one thing a dual runtime must never do. */
static const char *resolve_ctx(const management_command_t *c,unsigned *out)
{
    if(c->has_ctx){*out=c->ctx;return NULL;}
    if(bound_count()==1){*out=lowest_bound();return NULL;}
    return "ctx_required";
}
/* --- one-radio TX arbitration ----------------------------------------------
 *
 * Frames are built into `build` and handed to dual_sched, which owns the
 * decision of what goes on air next; tx_t still owns the transmission itself,
 * its CCA backoff, its abort paths and its completion guarantees. The two are
 * not alternatives: the scheduler arbitrates between contexts, the lifecycle
 * runs the one frame that won.
 *
 * What this changes for the host: V25 refused any command while a frame was in
 * flight, which with one radio and two contexts would mean either context's
 * steady one hertz poll could be dropped whenever the other held the radio.
 * A TX verb is now queued instead of refused. Control verbs -- BIND and the
 * three commit verbs -- still require a free radio, because they republish
 * configuration and bindings and touch the ACK gate, and doing that underneath
 * a transmission belonging to the other context buys nothing and risks the one
 * obligation this firmware cannot miss.
 */
static uint8_t build[DUAL_TX_MAC_MAX];
/* One second beyond the lifecycle's loosest watchdog, so the lifecycle always
 * acts first and this never fires. */
#define SCHED_BACKSTOP_US 3000000u

/* The management kind of the frame each context has outstanding. One byte per
 * context is enough, and is not a second copy of the queue's bookkeeping,
 * because the protocol allows exactly one outstanding management frame per
 * context: management_tx refuses while recovery.pending is set, and every
 * typed verb is additionally one-shot within its phase. The submit path below
 * asserts that the context's queue was empty, so if that invariant ever
 * stopped holding this would fail loudly rather than complete a frame against
 * the wrong kind. */
static uint8_t pending_kind[DUAL_CONTEXTS];
/* And whether that frame was the firmware's own automatic poll rather than a
 * host command. This cannot be derived from the frame's class: a host
 * MANAGEMENT_POLL is also TX_CLASS_POLL, and guessing would label its
 * completion AUTO_DONE instead of TXDONE, which is the record the host waits
 * on. */
static bool pending_automatic[DUAL_CONTEXTS];

static dual_tx_class_t tx_class_of(unsigned kind)
{
    return kind==M_POLL?TX_CLASS_POLL:kind==M_APP?TX_CLASS_APPLICATION:TX_CLASS_MANAGEMENT;
}

/* Submit refusals are reported with their own tokens rather than folded into
 * tx_busy: "the queue is full" and "that frame does not belong to this
 * context" are different faults and the second one is a security event. */
static const char *submit_reason(dual_tx_submit_t r)
{
    switch(r){
    case TX_SUBMIT_ACCEPTED:        return NULL;
    case TX_SUBMIT_BAD_CONTEXT:     return "sched_context";
    case TX_SUBMIT_QUEUE_FULL:      return "sched_queue_full";
    case TX_SUBMIT_DUPLICATE_ID:    return "sched_duplicate_id";
    case TX_SUBMIT_BAD_LENGTH:      return "sched_length";
    case TX_SUBMIT_TUPLE_MISMATCH:  return "sched_tuple_mismatch";
    }
    return "sched_unknown";
}

/* Hands the scheduler a built frame. `automatic` only selects the record name
 * at completion; the scheduler does not distinguish them. */
static const char *tx_submit(unsigned ctx,uint32_t id,unsigned kind,bool automatic,
                             size_t n,uint32_t now)
{
    dual_sched_stats_t before;dual_sched_stats(&before);
    if(before.queue_depth[ctx]!=0)return "sched_context_busy";
    dual_tx_submit_t r=dual_sched_submit(ctx,id,tx_class_of(kind),false,build,(uint8_t)n,now);
    const char *reason=submit_reason(r);
    if(reason)return reason;
    pending_kind[ctx]=(uint8_t)kind;pending_automatic[ctx]=automatic;
    return NULL;
}

/* Moves one queued frame onto the radio when the radio is free. RX and an
 * immediate ACK in progress win, which the scheduler enforces from the flags
 * passed here. */
static void sched_service(void)
{
    if(tx.state)return;
    const dual_tx_frame_t *f=NULL;
    uint32_t now=gate_hw_now_us();
    /* rx_busy and ack_busy are passed false, and that is deliberate rather
     * than an omission. The Nordic driver owns RX and auto-ACK precedence over
     * a transmit request: it defers or refuses a TX while receiving and while
     * an ACK is outstanding, and that is the mechanism V17..V25 have hardware
     * proof for. main.c has no truthful instantaneous "an ACK is on air right
     * now" signal -- `immediate_ack` is only whether ACK is enabled -- and
     * feeding the scheduler a guessed one would be worse than feeding it none,
     * because the counters would then read as measurements. The module's two
     * deferral counters therefore stay at zero in firmware; the module's own
     * tests exercise those paths.
     *
     * The deadline is one second beyond the lifecycle's loosest watchdog
     * (2 s). The lifecycle is the single watchdog and must always act first;
     * this one is a backstop whose firing would mean the lifecycle lost a
     * frame it owned. */
    if(!dual_sched_dispatch(now,false,false,now+SCHED_BACKSTOP_US,&f)||!f)return;
    uint32_t p=irq_lock();
    tx.raw[0]=(uint8_t)(f->len+2);memcpy(tx.raw+1,f->mac,f->len);
    tx.id=f->host_id;tx.session=1;tx.ctx=f->ctx;tx.kind=pending_kind[f->ctx];
    tx.automatic=pending_automatic[f->ctx];
    tx.ack_present=false;tx.start_us=tx.intent_us=now;tx.pre_air_cca=false;tx.cca_initialized=false;tx.mac_retries=0;
    tx.cca_attempts=tx.cca_busy=0;tx.cca_be=3;tx.rf_start_us=0;tx.end_us=0;
    tx.abort_started_us=0;tx.ack_fcf=0;tx.ack_dsn=0;tx.callback_seen=false;
    tx.terminal=false;tx.output_queued=false;tx.abort_reason=0;tx.cleanup=0;
    tx.submitted=false;accepted_count++;tx.state=1;
    irq_unlock(p);
}

static void command(const char *str)
{
    management_command_t c;const char *error=management_parse(str,&c);
    if(error){stop_all_loss();snprintf(line,sizeof(line),RADIO_PREFIX " ERROR boot=%s reason=%s\n",boot,error);emit();return;}
    if(c.kind!=M_INFO && strcmp(c.boot,boot))error="boot_mismatch";
    else if(has_id && c.id<=last_id)error="id_reused";
    if(error)goto fail;has_id=true;last_id=c.id;
    if(c.kind==M_INFO){snprintf(line,sizeof(line),RADIO_PREFIX " INFO boot=%s id=%lu identity=airnanny_dual_pan_runtime_v28 version=28 wire=%u contexts=2 config_generation=%lu max_run_seconds=3900 max_total_polls_per_context=3600 max_discovery_scans=3 tx_power_dbm=%d channel=21 application_tx=typed_fan_once crypto=host_only immediate_ack=%u pending_tx=%u session=%lu rx_revision=%lu rx_drop=%lu out_drop=%lu\n",boot,(unsigned long)c.id,(unsigned)RADIO_WIRE_VERSION,(unsigned long)config_generation,(int)nrf_802154_tx_power_get(),immediate_ack,tx.state!=0,(unsigned long)sessions[lowest_bound()].association.session,(unsigned long)gate_hw_revision(),(unsigned long)gate_hw_dropped(),(unsigned long)out_drop);emit();return;}
    /* STATS is a read-only global report and the only place the admission and
     * scheduler counters become observable from the host. It is answered before
     * the capture-loss check below on purpose: when evidence has been lost, the
     * counters are the most useful thing left to read, and refusing to report
     * them is the opposite of what a diagnostic should do. */
    if(c.kind==M_STATS){
        dual_stats_t rx;dual_stats_get(&rx);
        dual_sched_stats_t sch;dual_sched_stats(&sch);
        if(!dual_format_stats(line,sizeof(line),boot,c.id,config_generation,&rx,&sch,
                              starved_polls,sched_routing_faults)){
            error="stats_truncated";goto fail;
        }
        emit();return;
    }
    if(c.kind==M_STATUS){status(c.id,c.has_ctx?c.ctx:DUAL_CONTEXTS);return;}
    if(c.kind==M_END){if(c.session!=sessions[lowest_bound()].association.session){error="session_mismatch";goto fail;}tx_terminal_request(ABORT_END);stop_all_loss();tx_service();status(c.id,c.has_ctx?c.ctx:DUAL_CONTEXTS);return;}
    if(out_drop||gate_hw_dropped()||gate_hw_revision()==UINT32_MAX){error="capture_loss";goto fail;}
    /* Control verbs republish configuration, bindings and the ACK gate, so
     * they still require a free radio exactly as in V25. TX verbs no longer
     * do: they are queued per context, which is what stops one context's
     * transmission from dropping the other's one hertz poll. */
    if(tx.state&&(c.kind==M_BIND||c.kind==M_DISCOVERY_COMMIT||
                  c.kind==M_SHORT_COMMIT||c.kind==M_ACTIVE)){error="tx_busy";goto fail;}
    unsigned ctx;
    error=resolve_ctx(&c,&ctx);if(error)goto fail;
    if(ctx>=DUAL_CONTEXTS){error="ctx_invalid";goto fail;}
    last_ctx=ctx;
    commission_t *s=&sessions[ctx];
    if(c.kind==M_BIND){
        error=management_resume(s,&c,gate_hw_now_us());if(error)goto fail;set_ack(false);
        /* Publish this context to the admission layer. Under DUAL_PAN_GATE the
         * driver's own destination filter is replaced, so the PIB PAN and short
         * address no longer take part in admission and are not written here;
         * the paired table below is what decides reception and ACK. V25 wrote
         * the PIB and had to stop the radio to do it, which in a dual runtime
         * would disturb the other context for no benefit. */
        dual_config_t cfg=*dual_config_current();
        cfg.enabled=true;cfg.channel=21;cfg.generation=++config_generation;
        cfg.ctx[ctx].enabled=true;
        cfg.ctx[ctx].pan_id=s->keys.pan;
        cfg.ctx[ctx].local_short=s->keys.short_address;
        cfg.ctx[ctx].ieee_valid=true;
        memcpy(cfg.ctx[ctx].local_ieee,s->keys.raw,8);
        uint32_t fence=irq_lock();
        bool published=dual_config_commit_locked(&cfg);
        irq_unlock(fence);
        if(!published){error="config_rejected";goto fail;}
        gate_hw_config_generation(cfg.generation);
        dual_binding_t bind;memset(&bind,0,sizeof(bind));
        bind.pan=s->keys.pan;bind.short_address=s->keys.short_address;bind.keyseq=s->keys.keyseq;
        memcpy(bind.raw,s->keys.raw,8);memcpy(bind.tc,s->keys.tc,8);
        if(!dual_binding_set(ctx,&bind)){error="binding_rejected";goto fail;}
        if(!nrf_802154_receive()){error="receive_failed";goto fail;}
        radio_service();status(c.id,ctx);return;
    }
    if(c.kind==M_DISCOVERY_COMMIT||c.kind==M_SHORT_COMMIT||c.kind==M_ACTIVE){
        error=management_control(s,&c,gate_hw_now_us());if(error)goto fail;

        if(c.kind==M_SHORT_COMMIT){
            /* A reassigned short changes this context's entry only, published
             * atomically; the radio is not stopped and the other context keeps
             * receiving and answering throughout. */
            dual_config_t cfg=*dual_config_current();
            cfg.generation=++config_generation;
            cfg.ctx[ctx].local_short=s->keys.short_address;
            uint32_t fence=irq_lock();
            bool published=dual_config_commit_locked(&cfg);
            irq_unlock(fence);
            if(!published){error="short_config_rejected";goto fail;}
            gate_hw_config_generation(cfg.generation);
            dual_binding_t bind;memset(&bind,0,sizeof(bind));
            bind.pan=s->keys.pan;bind.short_address=s->keys.short_address;bind.keyseq=s->keys.keyseq;
            memcpy(bind.raw,s->keys.raw,8);memcpy(bind.tc,s->keys.tc,8);
            if(!dual_binding_set(ctx,&bind)){error="short_binding_rejected";goto fail;}
            radio_service();
        }
        status(c.id,ctx);return;
    }
    if(c.kind==M_BEACON){
        /* Beacons arrive regardless: promiscuous RX delivers every CRC-valid
         * frame and the admission layer only decides the ACK. So no PIB change
         * and no radio stop here, which is what let the other context keep
         * running during a scan. */
        s->recovery.scan_floor=gate_hw_revision();
        dual_binding_scanning(ctx,true);
    }
    /* The frame is built into `build`, not straight into tx.raw: it may have to
     * wait for the other context to finish with the radio. management_tx has
     * already committed this context's session state to it by the time it
     * returns, which is exactly why the queue can hold at most one frame per
     * context and why the submit path asserts that. */
    uint32_t p=irq_lock();size_t n=0;
    uint32_t now=gate_hw_now_us();
    error=management_tx(s,&c,now,build,&n);
    if(!error)error=tx_submit(ctx,c.id,c.kind,false,n,now);
    irq_unlock(p);
    if(error)goto fail;
    char mac[251];hex_le(build,n,mac,false);snprintf(line,sizeof(line),RADIO_PREFIX " TXACCEPT boot=%s id=%lu ctx=%u session=1 class=%s mac=%s retry=0\n",boot,(unsigned long)c.id,ctx,management_class(c.kind),mac);emit();
    /* Accepted is not the same as on air. Try to start it at once so a free
     * radio is not left idle until the next loop iteration. */
    sched_service();return;
fail:
    /* A command fault belongs to the context it named, when it named one. */
    if(c.has_ctx&&c.ctx<DUAL_CONTEXTS)stop_ctx_loss(c.ctx);else stop_all_loss();
    snprintf(line,sizeof(line),RADIO_PREFIX " ERROR boot=%s id=%lu reason=%s\n",boot,(unsigned long)c.id,error);emit();
}
/* One radio serialises the two contexts by construction: nothing is offered
 * while a frame is in flight. Round robin decides who is offered first, so a
 * context cannot be starved by the other's steady one hertz polling, and a
 * context that was ready but not served is counted. */
static void auto_poll_service(void){
    if(oh-ot>24)return;
    uint32_t now=gate_hw_now_us();
    /* Both contexts are offered a turn, not just one: a poll goes into that
     * context's own queue rather than onto the radio, so a frame in flight no
     * longer blocks the other context from being built. The round robin here
     * decides who is offered first when both are due in the same iteration;
     * the scheduler decides who reaches the radio first.
     *
     * starved_polls is kept as the firmware's own count of a context that was
     * due and could not be offered -- which now means its own queue was still
     * occupied, not that the radio was busy. */
    for(unsigned step=1;step<=DUAL_CONTEXTS;step++){
        unsigned c=(poll_turn+step)%DUAL_CONTEXTS;
        commission_t *s=&sessions[c];
        if(s->recovery.phase==R_STOPPED)continue;
        dual_sched_stats_t q;dual_sched_stats(&q);
        if(q.queue_depth[c]!=0){
            if(s->recovery.window&&!s->recovery.pending&&now>=s->recovery.poll_due)
                if(starved_polls!=UINT32_MAX)starved_polls++;
            continue;
        }
        size_t n=10;
        if(!management_auto_poll(s,now,build))continue;
        if(tx_submit(c,s->recovery.request_id,M_POLL,true,n,now)){
            /* The frame was built and the session already counted it, so a
             * refusal here cannot be ignored: that context's state no longer
             * matches what is queued. */
            stop_ctx_loss(c);continue;
        }
        poll_turn=c;
        char mac[21];hex_le(build,n,mac,false);
        snprintf(line,sizeof(line),RADIO_PREFIX " AUTO_ACCEPT boot=%s id=%lu ctx=%u session=1 class=MANAGEMENT_POLL mac=%s retry=0 time_us=%lu poll=%lu\n",boot,(unsigned long)s->recovery.request_id,c,mac,(unsigned long)now,(unsigned long)s->recovery.polls);emit();
    }
    sched_service();
}
void nrf_802154_transmitted_raw(const uint8_t *p,uint8_t *ack,int8_t r,uint8_t l){
    (void)r;(void)l;uint32_t v=irq_lock();
    if(p==tx.raw&&tx.state==OWNER_RADIO){tx.end_us=gate_hw_now_us();tx.callback_seen=true;tx.ack_present=ack!=NULL;tx.ack_fcf=ack?ack[1]:0;tx.ack_dsn=ack?ack[3]:0;tx.result=ATX_OK;if((p[1]&0x20)&&(!ack||ack[0]!=5||ack[2]!=0||(ack[1]!=2&&ack[1]!=18)||ack[3]!=p[3]))tx.result=ATX_INVALID_ACK;__DMB();tx.state=OWNER_CALLBACK;}
    else if(p==tx.raw){late_callbacks++;if(tx.state==OWNER_BACKOFF){tx.state=OWNER_RADIO;tx_terminal_request(ABORT_LOSS);commission_stop(owner());}}
    irq_unlock(v);if(ack)nrf_802154_buffer_free_raw(ack);
}
void nrf_802154_tx_started(const uint8_t *p){uint32_t v=irq_lock();if(p==tx.raw&&tx.state==OWNER_RADIO){if(tx.rf_start_us){tx_terminal_request(ABORT_LOSS);commission_stop(owner());}else tx.rf_start_us=gate_hw_now_us();}else if(p==tx.raw&&tx.state==OWNER_BACKOFF){tx.rf_start_us=gate_hw_now_us();tx.state=OWNER_RADIO;tx_terminal_request(ABORT_LOSS);commission_stop(owner());}irq_unlock(v);}
void nrf_802154_transmit_failed(const uint8_t *p,nrf_802154_tx_error_t e){
    uint32_t v=irq_lock();
    if(p==tx.raw&&tx.state==OWNER_RADIO){tx.end_us=gate_hw_now_us();tx.callback_seen=true;
    switch(e){case NRF_802154_TX_ERROR_NO_ACK:tx.result=ATX_NO_ACK;break;case NRF_802154_TX_ERROR_BUSY_CHANNEL:tx.result=ATX_CCA_FAIL;tx.pre_air_cca=cca_pre_air_proven();break;case NRF_802154_TX_ERROR_INVALID_ACK:tx.result=ATX_INVALID_ACK;break;case NRF_802154_TX_ERROR_ABORTED:tx.result=ATX_ABORTED;break;default:tx.result=ATX_ERROR;}
    __DMB();tx.state=OWNER_CALLBACK;}else if(p==tx.raw){late_callbacks++;if(tx.state==OWNER_BACKOFF){tx.state=OWNER_RADIO;tx_terminal_request(ABORT_LOSS);commission_stop(owner());}}
    irq_unlock(v);
}
static void receive_service(void)
{
    gate_event_t e;if(!gate_hw_pop(&e))return;
    /* A frame is offered to the context the clear header selected, and to no
     * other. Anything outside both contexts is reported and offered to neither;
     * a diagnostic tag must never look like membership. */
    unsigned ctx=e.match==MATCH_CTX0?0u:e.match==MATCH_CTX1?1u:DUAL_CONTEXTS;
    bool clean_ack=e.ack_started&&e.ack_completed&&!e.deadline_miss;
    if(ctx<DUAL_CONTEXTS)management_observe(&sessions[ctx],e.mac,e.length,e.revision,e.time_us,clean_ack);
    else for(unsigned c=0;c<DUAL_CONTEXTS;c++)
        /* A frame the classifier could not attribute is offered to both
         * contexts, exactly as the single-context predecessor offered every
         * frame to its one session. The classifier is scoped to addressed DATA
         * because that is what an immediate ACK may answer; it deliberately
         * says nothing about a beacon, which is frame type 0 with no
         * destination and therefore unsupported to it. Routing must not depend
         * on it for those, or discovery would never see a beacon.
         *
         * This cannot cross-credit: management_observe validates the PAN and
         * both identities against that context's own keys, for the beacon path
         * and the response path alike, so the per-context predicate is the
         * gate and an attributed frame still reaches only its own context. */
        management_observe(&sessions[c],e.mac,e.length,e.revision,e.time_us,clean_ack);
    char ctxname[8];
    if(ctx<DUAL_CONTEXTS)snprintf(ctxname,sizeof(ctxname),"%u",ctx);else snprintf(ctxname,sizeof(ctxname),"none");
    char mac[251];hex_le(e.mac,e.length,mac,false);
    snprintf(line,sizeof(line),RADIO_PREFIX " RX boot=%s ctx=%s match=%s reason=%s config_generation=%lu session=%lu revision=%lu channel=21 time_us=%lu ack_address_us=%lu ack_start_us=%lu ack_end_us=%lu rssi=%d lqi=%u fcs_ok=1 ack_started=%u ack_completed=%u deadline_miss=%u mac=%s\n",
        boot,ctxname,dual_match_name(e.match),dual_reason_name(e.header.reason),(unsigned long)e.config_generation,(unsigned long)e.session,(unsigned long)e.revision,(unsigned long)e.time_us,
        (unsigned long)e.ack_address_us,(unsigned long)e.ack_start_us,(unsigned long)e.ack_end_us,
        e.rssi,e.lqi,e.ack_started,e.ack_completed,e.deadline_miss,mac);
    if(open)emit();
}
/* Bounded queue drain precedes all RX response-window verdicts. No RF deadline
 * extension: management_observe still validates the original event timestamp.
 * An incomplete pre-cutoff callback gets at most 2ms foreground grace, then
 * fails closed; it never licenses another transmission. */
static void management_receive_service(void)
{
    for(unsigned i=0;i<GATE_RING_SIZE;i++)receive_service();
    uint32_t p=irq_lock(),now=gate_hw_now_us();
    for(unsigned c=0;c<DUAL_CONTEXTS;c++){
        commission_t *s=&sessions[c];
        recovery_transport_t *q=&s->recovery;
        bool closing=s->phase==G_MANAGEMENT&&q->deadline_us&&now>=q->deadline_us&&
            (q->phase==R_SCANNING||q->window);
        /* The ring is shared, so a stalled drain is a shared-evidence fault and
         * is reported as such; the verdict still stops only the context whose
         * window it invalidated, because the other context's records are
         * unaffected by its neighbour's deadline. */
        if(closing&&!gate_hw_cutoff_drained(q->deadline_us)){
            if(now-q->deadline_us>=2000u){rx_cutoff_stalled=true;commission_stop(s);}
        }else management_tick(s,now);
    }
    irq_unlock(p);
}
static void cdc_event(app_usbd_class_inst_t const *inst,app_usbd_cdc_acm_user_event_t event)
{
    (void)inst;
    if(event==APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN){open=true;input_length=0;discard=false;app_usbd_cdc_acm_read(&cdc,&byte,1);}
    else if(event==APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE){
        tx_terminal_request(ABORT_USB);open=false;command_pending=false;input_length=0;discard=false;
        /* Keep the asynchronous CDC buffer immutable until TX_DONE. If abort produces
           no completion, the transport fails closed and needs a device reboot. */
        oh=busy?ot+1:ot;
        stop_all_loss();set_ack(false);
    }
    else if(event==APP_USBD_CDC_ACM_USER_EVT_TX_DONE){busy=false;if(ot!=oh)ot++;}
    else if(event==APP_USBD_CDC_ACM_USER_EVT_RX_DONE){do{
        if(byte=='\r' || byte=='\n'){
            if(discard)line_error=true;
            else if(input_length){input[input_length]=0;if(command_pending)command_overflow=true;else{memcpy(pending_command,input,input_length+1);command_pending=true;}}
            input_length=0;discard=false;
        }else if(byte<32 || byte>126)discard=true;
        else if(input_length<sizeof(input)-1 && !discard)input[input_length++]=(char)byte;
        else discard=true;
    }while(app_usbd_cdc_acm_read(&cdc,&byte,1)==NRF_SUCCESS);}
}
static void usb_event(app_usbd_event_type_t e)
{
    if(e==APP_USBD_EVT_POWER_DETECTED){if(!nrf_drv_usbd_is_enabled())app_usbd_enable();}
    else if(e==APP_USBD_EVT_POWER_READY)app_usbd_start();
    else if(e==APP_USBD_EVT_POWER_REMOVED){open=false;stop_all_loss();set_ack(false);app_usbd_stop();}
    else if(e==APP_USBD_EVT_STOPPED)app_usbd_disable();
}
void nrf_802154_received_timestamp_raw(uint8_t *p,int8_t r,uint8_t l,uint32_t ts){(void)ts;gate_hw_receive(p,r,l);}
void nrf_802154_tx_ack_started(const uint8_t *p){(void)p;gate_hw_ack_started();}
void nrf_802154_receive_failed(nrf_802154_rx_error_t e){if(e==NRF_802154_RX_ERROR_INVALID_FCS)gate_hw_crc_error();}
int main(void)
{
    static const app_usbd_config_t usb={.ev_state_proc=usb_event};APP_ERROR_CHECK(nrf_drv_clock_init());app_usbd_serial_num_generate();
    APP_ERROR_CHECK(app_usbd_init(&usb));APP_ERROR_CHECK(app_usbd_class_append(app_usbd_cdc_acm_class_inst_get(&cdc)));
    memset(sessions,0,sizeof(sessions));
    /* The starvation bound only drives a diagnostic counter and never reorders
     * work. One second is the observed per-context poll cadence, so a frame
     * still queued after that long is worth counting. */
    dual_sched_init(1000000u);
    random_boot();nrf_802154_init();if(!radio_power_configure())APP_ERROR_HANDLER(NRF_ERROR_INTERNAL);nrf_802154_channel_set(21);set_ack(false);nrf_802154_promiscuous_set(true);gate_hw_session(&sessions[0]);gate_hw_init();nrf_802154_receive();APP_ERROR_CHECK(app_usbd_power_events_enable());
    uint32_t last_drop=0,last_clock=gate_hw_now_us();
    for(;;){
        app_usbd_event_queue_process();
        uint32_t clock=gate_hw_now_us();
        /* The 32 bit microsecond timer wraps after about 71.6 minutes. A long
         * soak must be started with that in mind: a wrap stops the session. */
        if(clock<last_clock){stop_all_loss();}
        last_clock=clock;
        uint32_t drop=gate_hw_dropped();if(drop!=last_drop){last_drop=drop;stop_all_loss();}
        /* Publish callback-created response windows before observing queued RX. */
        tx_service();management_receive_service();
        for(unsigned c=0;c<DUAL_CONTEXTS;c++)
            if(sessions[c].association.state==A_TIMEOUT||sessions[c].association.state==A_UNCERTAIN||sessions[c].association.state==A_REJECTED)
                stop_ctx_loss(c);

        drop=gate_hw_dropped();if(drop!=last_drop){last_drop=drop;stop_all_loss();}
        radio_service();
        auto_poll_service();
        /* The lifecycle is the single watchdog and always acts first, so this
         * must never act. If it does, the scheduler was holding a frame the
         * lifecycle had lost, which means neither one's view of the radio can
         * be trusted any more. */
        /* Counted into the same number as a refused completion: both mean the
         * lifecycle and the scheduler disagree about which frame owns the
         * radio, which is one failure class and deserves one observable
         * counter rather than a flag nobody reads. */
        if(dual_sched_poll(clock)){
            if(sched_routing_faults!=UINT32_MAX)sched_routing_faults++;
            stop_all_loss();
        }
        if(open && oh-ot<12){
            if(line_error || command_overflow){line_error=command_overflow=command_pending=false;snprintf(line,sizeof(line),RADIO_PREFIX " ERROR boot=%s reason=input_overflow_or_nonascii\n",boot);emit();stop_all_loss();}
            else if(command_pending){command_pending=false;command(pending_command);}
        }
        if(open && !busy && oh!=ot && app_usbd_cdc_acm_write(&cdc,output[ot%32],strlen(output[ot%32]))==NRF_SUCCESS)busy=true;
    }
}

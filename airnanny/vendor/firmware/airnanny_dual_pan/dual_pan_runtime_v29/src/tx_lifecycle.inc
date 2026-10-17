/* Shared TX ownership infrastructure. No frame builders/crypto/ISR logging. */
enum { OWNER_FREE=0, OWNER_QUEUED=1, OWNER_RADIO=2, OWNER_CALLBACK=3, OWNER_ABORTING=4, OWNER_QUARANTINED=5, OWNER_BACKOFF=6 };
enum { ABORT_NONE=0, ABORT_WATCHDOG=1, ABORT_END=2, ABORT_USB=3, ABORT_LOSS=4 };
static uint32_t accepted_count,terminal_count,late_callbacks,abort_calls,watchdog_count;
/* Disagreement between this lifecycle and the scheduler about which frame owns
 * the radio. Must stay zero. Two conditions reach it: a completion the
 * scheduler refused to route, and the scheduler's deadline backstop firing on a
 * frame the lifecycle should already have ended. Both are the same failure
 * class, and either one stops the runtime. */
static uint32_t sched_routing_faults;

/* The lifecycle's result vocabulary mapped onto the scheduler's. An abort is
 * reported as an abort whatever stage it happened at, because that is what the
 * host is told, and ATX_OK with an abort pending is not a success. */
static dual_tx_result_t tx_result_of(unsigned abort_reason,unsigned result)
{
    if(abort_reason)return TX_RESULT_ABORTED;
    switch(result){
    case ATX_OK:          return TX_RESULT_OK;
    case ATX_NO_ACK:      return TX_RESULT_NO_ACK;
    case ATX_INVALID_ACK: return TX_RESULT_INVALID_ACK;
    case ATX_CCA_FAIL:    return TX_RESULT_CCA_FAIL;
    case ATX_ABORTED:     return TX_RESULT_ABORTED;
    default:              return TX_RESULT_ERROR;
    }
}
static bool reboot_required;
static const char *owner_name(unsigned s){static const char *v[]={"free","queued","radio_submitted","callback_received","aborting","quarantined","cca_backoff"};return s<7?v[s]:"invalid";}
static const char *abort_name(unsigned r){return r==ABORT_WATCHDOG?"tx_watchdog_abort":r==ABORT_END?"tx_end_abort":r==ABORT_USB?"tx_usb_abort":"tx_terminal_abort";}
static const char *driver_phase(void){
#ifdef ASSOC_HOST_TEST
    return mock_core_sleep?"sleep":mock_waiting_ack&&mock_dma?"waiting_ack":mock_dma?"tx":"rx";
#else
    switch(nrf_802154_core_state_get()){
        case RADIO_STATE_SLEEP:return "sleep";case RADIO_STATE_FALLING_ASLEEP:return "falling_asleep";
        case RADIO_STATE_RX_ACK:return "waiting_ack";case RADIO_STATE_CCA_TX:return "cca_tx";case RADIO_STATE_TX:return "tx";
        default:return "rx_or_other";
    }
#endif
}
static bool driver_quiescent(void){
#ifdef ASSOC_HOST_TEST
    return mock_core_sleep && mock_radio_disabled;
#else
    /* Public state_get maps FALLING_ASLEEP to SLEEP: insufficient alone. */
    return nrf_802154_core_state_get()==RADIO_STATE_SLEEP && NRF_RADIO->STATE==RADIO_STATE_STATE_Disabled;
#endif
}
static bool tx_terminal_request(unsigned reason){
    uint32_t p=irq_lock();
    bool claimed=false;
    if(tx.state==OWNER_QUEUED||tx.state==OWNER_BACKOFF||tx.state==OWNER_RADIO){
        claimed=true;
        tx.abort_reason=reason;tx.abort_started_us=gate_hw_now_us();
        tx.abort_attempted=false;tx.abort_accepted=false;
        if(reason==ABORT_WATCHDOG)watchdog_count++;
        if(tx.state==OWNER_QUEUED||tx.state==OWNER_BACKOFF){tx.result=ATX_ABORTED;tx.end_us=tx.abort_started_us;tx.cleanup=1;tx.state=OWNER_CALLBACK;}
        else tx.state=OWNER_ABORTING;
    }
    irq_unlock(p);
    return claimed;
}
static void tx_finish(bool ambiguous){
    if(tx.terminal)return;
    tx.terminal=true;terminal_count++;
    if(ambiguous){tx.cleanup=2;reboot_required=true;tx.state=OWNER_QUARANTINED;}
    else {tx.cleanup=1;tx.state=OWNER_FREE;}
    if(owner()->phase==G_STOPPED){owner()->recovery.pending=false;owner()->recovery.window=false;}
    /* A clean miss is one the radio finished normally: no abort, no ambiguity,
     * and an outcome that says the frame went nowhere useful rather than that
     * the lifecycle lost track of it. */
    else management_done(owner(),tx.result==ATX_OK,
        !ambiguous&&!tx.abort_reason&&(tx.result==ATX_NO_ACK||tx.result==ATX_INVALID_ACK||tx.result==ATX_CCA_FAIL),
        tx.kind,tx.end_us);
    /* Release the radio in the scheduler and route the result to the context
     * that submitted it. The lifecycle is the single watchdog, so this is the
     * one and only place the scheduler is told the frame is over; a host id
     * that does not match the in-flight frame is a routing error there and
     * completes nothing, rather than freeing some other context's frame. */
    if(!dual_sched_complete(tx.id,tx_result_of(tx.abort_reason,tx.result),tx.end_us))
        if(sched_routing_faults!=UINT32_MAX)sched_routing_faults++;
    snprintf(line,sizeof(line),RADIO_PREFIX " %s boot=%s id=%lu ctx=%u session=%lu result=%s time_us=%lu rf_start_us=%lu ack_present=%u ack_fcf=%u ack_dsn=%u poll=%lu application_tx=typed_type07_repeat cleanup=%s reboot_required=%u terminal_seq=%lu cca_attempts=%u cca_busy=%u cca_preair=%u diag_dsn=%lu diag_wait=%lu diag_address=%lu diag_end=%lu diag_match=%lu diag_crc=%lu diag_ack_fcf=%lu diag_ack_dsn=%lu diag_timeouts=%lu submit_reason=%lu submit_state=%lu rx_admission_deferrals=%lu mac_retries=%u\n",
        tx.automatic?"AUTO_DONE":"TXDONE",boot,(unsigned long)tx.id,tx.ctx,(unsigned long)tx.session,
        tx.abort_reason?abort_name(tx.abort_reason):assoc_tx_name(tx.result),(unsigned long)tx.end_us,(unsigned long)tx.rf_start_us,
        tx.ack_present,tx.ack_fcf,tx.ack_dsn,(unsigned long)owner()->recovery.polls,ambiguous?"unproven":"safe",reboot_required,(unsigned long)terminal_count,tx.cca_attempts,tx.cca_busy,tx.pre_air_cca,(unsigned long)ack_trace.dsn,(unsigned long)ack_trace.wait,(unsigned long)ack_trace.address,(unsigned long)ack_trace.end,(unsigned long)ack_trace.match,(unsigned long)ack_trace.crc,(unsigned long)ack_trace.ack_fcf,(unsigned long)ack_trace.ack_dsn,(unsigned long)ack_trace.timeouts,(unsigned long)submission_trace.reason,(unsigned long)submission_trace.state,(unsigned long)tx.rx_admission_deferrals,tx.mac_retries);
    tx.output_queued=emit();
}
/* V28: the one place a frame is sent again. Only a rejoin-chain frame that
 * really went on air (a TX-start was seen) and then drew no ACK or a bad one,
 * with no abort pending, the port open and the context live, and only while
 * the host's intent is young. Everything the next submission needs is reset
 * as for a fresh frame -- including rf_start_us, because tx_started treats a
 * second start of one submission as a fault -- but the bytes, the DSN and the
 * frame counter are the same, and intent_us is not moved. The context learns
 * the outcome once, from the last attempt, through tx_finish. */
static bool tx_retry_eligible(void){
    return tx.kind==M_REJOIN||tx.kind==M_ANNOUNCE||tx.kind==M_TIMEOUT;
}
static bool tx_retry(uint32_t now){
    if(tx.state!=OWNER_CALLBACK||tx.abort_reason||tx.automatic||!tx_retry_eligible())return false;
    if(tx.result!=ATX_NO_ACK&&tx.result!=ATX_INVALID_ACK)return false;
    if(!tx.callback_seen||!tx.rf_start_us)return false;
    if(tx.mac_retries>=MAC_MAX_FRAME_RETRIES||!open||owner()->phase==G_STOPPED)return false;
    if(now-tx.intent_us>=TX_RETRY_WINDOW_US)return false;
    uint32_t p=irq_lock();
    tx.mac_retries++;
    tx.start_us=now;tx.rf_start_us=0;tx.end_us=0;tx.result=ATX_OK;
    tx.ack_present=false;tx.ack_fcf=0;tx.ack_dsn=0;
    tx.submitted=false;tx.callback_seen=false;tx.pre_air_cca=false;
    tx.cca_initialized=false;tx.cca_attempts=tx.cca_busy=0;tx.cca_be=CCA_MIN_BE;
    tx.state=OWNER_QUEUED;
    irq_unlock(p);
    return true;
}
static void tx_service(void){
    uint32_t now=gate_hw_now_us();
    /* Before the watchdog is chosen: a requeued attempt has no rf_start yet. */
    tx_retry(now);
    uint32_t watchdog_us=tx.kind==M_POLL?1500000u:2000000u;
    /* Time starts at the accepted host intent, never at a repeated CCA. */
    if(cca_eligible()&&!tx.rf_start_us)watchdog_us=CCA_ACQUISITION_US;
    if(tx.state==OWNER_CALLBACK&&tx.result==ATX_CCA_FAIL&&tx.pre_air_cca&&!tx.abort_reason){
        tx.cca_busy++;
        if(cca_eligible()&&tx.cca_attempts<CCA_MAX_ATTEMPTS&&now-tx.start_us<CCA_ACQUISITION_US&&open&&owner()->phase!=G_STOPPED){
            if(tx.cca_be<CCA_MAX_BE)tx.cca_be++;
            cca_schedule(now); /* old direct callback fully returned; no TX DMA */
        }
    }
    if(tx.state==OWNER_BACKOFF&&now-tx.start_us>=CCA_ACQUISITION_US){
        tx.result=ATX_CCA_FAIL;tx.end_us=now;tx.state=OWNER_CALLBACK;
    }
    /* Callback ownership wins even if main was delayed beyond the deadline. */
    uint32_t p=irq_lock();bool expired=(tx.state==OWNER_QUEUED||tx.state==OWNER_BACKOFF||tx.state==OWNER_RADIO)&&(now-tx.start_us>watchdog_us||now-tx.intent_us>TX_INTENT_LIMIT_US);irq_unlock(p);
    if(expired&&tx_terminal_request(ABORT_WATCHDOG)){stop_ctx_loss(tx.ctx);}
    if((tx.state==OWNER_QUEUED||tx.state==OWNER_BACKOFF||tx.state==OWNER_RADIO)&&(owner()->phase==G_STOPPED||!open)){tx_terminal_request(open?ABORT_LOSS:ABORT_USB);}
    if(tx.state==OWNER_QUEUED&&tx.automatic&&(now-tx.start_us>20000u||now>=owner()->recovery.deadline_us)){tx_terminal_request(ABORT_LOSS);stop_ctx_loss(tx.ctx);}
    if(tx.state==OWNER_QUEUED&&(tx.automatic||(!busy&&oh==ot))){
        if(cca_eligible()&&!tx.cca_initialized){tx.cca_initialized=true;cca_schedule(now);}
    }
    if((tx.state==OWNER_BACKOFF||(tx.state==OWNER_QUEUED&&(tx.automatic||(!busy&&oh==ot))))&&(!cca_eligible()||(int32_t)(now-tx.cca_due_us)>=0)){
        /* Auto response polls retain one CCA and the inherited 20ms queue bound;
         * additionally reserve worst PHR127/SHR/CCA/ramp/7000us ACK time. */
        if(tx.automatic&&(now>=owner()->recovery.deadline_us||owner()->recovery.deadline_us-now<12000u)){
            tx_terminal_request(ABORT_LOSS);stop_ctx_loss(tx.ctx);
        }else{
            p=handoff_lock();
            /* USB/END cannot interleave check and ownership handoff. Driver uses
             * direct critical sections; inline callbacks can only claim RADIO. */
            if(tx.state==OWNER_QUEUED||tx.state==OWNER_BACKOFF){
                uint32_t handoff_now=gate_hw_now_us();
                /* Reserve 32 symbols (512us): ramp40 + CCA128 + turnaround192
                 * + ramp-down6 < 512. No deferred scheduler in pinned singlePHY. */
                if(tx.automatic&&(handoff_now>=owner()->recovery.deadline_us||owner()->recovery.deadline_us-handoff_now<12000u)){
                    tx_terminal_request(ABORT_LOSS);commission_stop(owner());set_ack(false);
                }else if(cca_eligible()&&handoff_now-tx.start_us>=CCA_ACQUISITION_US-512u){
                    tx.result=ATX_CCA_FAIL;tx.end_us=handoff_now;tx.state=OWNER_CALLBACK;
                }else{
                /* Read-only admission check: do not interrupt an ongoing PSDU or
                 * immediate ACK. Keep the same immutable intent/20ms deadline.
                 * No driver submission, TX DMA or attempt occurs while busy.
                 * A race after this observation still stops on raw API false. */
                if(nrf_802154_core_tx_admission_busy()){
                    tx.rx_admission_deferrals++;
                }else{
                tx.state=OWNER_RADIO;tx.submitted=true;tx.callback_seen=false;tx.pre_air_cca=false;tx.cca_attempts++;
                ack_trace_reset(tx.raw[3]);
                submission_trace_reset();
                bool accepted=nrf_802154_transmit_raw(tx.raw,true);
                if(!accepted&&tx.state==OWNER_RADIO){
                    /* Pinned direct raw API uses immediate=false: its only false
                     * exits precede mp_tx_data assignment and tx_init. The prior
                     * slot is free/proven RX; no new TX DMA was acquired. Do not
                     * sleep/abort an unrelated RX or immediate ACK. No retry. */
                    tx.result=ATX_ERROR;tx.end_us=gate_hw_now_us();tx.callback_seen=false;tx.state=OWNER_CALLBACK;
                }
                } /* one actual submission after RX admission */
                }
            }
            handoff_unlock(p);
        }
    }
    if(tx.state==OWNER_ABORTING){
        if(!tx.abort_attempted){
            tx.abort_attempted=true;abort_calls++;
            /* Main context, IRQs enabled. Direct driver may callback synchronously.
             * ABORTING claim rejects it; buffer is still retained. Never retry. */
            tx.abort_accepted=nrf_802154_sleep();
        }
        now=gate_hw_now_us();
        if(tx.abort_accepted&&driver_quiescent()){tx.end_us=now;tx.result=ATX_ABORTED;tx_finish(false);}
        else if(!tx.abort_accepted||now-tx.abort_started_us>=20000u){tx.end_us=now;tx.result=ATX_ABORTED;tx_finish(true);}
    }
    if(tx.state==OWNER_CALLBACK)tx_finish(false);
}

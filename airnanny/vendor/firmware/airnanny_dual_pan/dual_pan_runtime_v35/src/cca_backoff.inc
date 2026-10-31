/* One immutable PSDU, firmware-owned pre-air acquisition only. */
#define CCA_MIN_BE 3u
#define CCA_MAX_BE 5u
#define CCA_MAX_ATTEMPTS 4u /* copied Nordic conservative count, NOT four retries */
#define CCA_UNIT_US 320u
#define CCA_ACQUISITION_US 40000u
static bool cca_pre_air_proven(void){
#ifdef ASSOC_HOST_TEST
 return tx.submitted&&tx.rf_start_us==0&&mock_cca_rx&&!mock_dma&&!mock_ack_timer;
#else
#if NRF_802154_CSMA_CA_ENABLED || !NRF_802154_TX_STARTED_NOTIFY_ENABLED
#error Requires pinned non-CSMA direct driver and TX-start notifications
#endif
 return tx.submitted&&tx.rf_start_us==0&&nrf_802154_core_state_get()==RADIO_STATE_RX;
#endif
}
static bool cca_eligible(void){
 /* Association builder shape is accepted by this shared MAC policy for a future
  * already-typed adapter. No Association USB command or commissioning is enabled. */
 bool association=tx.raw[0]==21&&tx.raw[1]==0x23&&tx.raw[2]==0xc8&&tx.raw[18]==1&&tx.raw[19]==0x80;
 return !tx.automatic&&(association||tx.kind==M_BEACON||tx.kind==M_REJOIN||tx.kind==M_ANNOUNCE||tx.kind==M_TIMEOUT||tx.kind==M_POLL);
}
static uint32_t cca_random(void){
#ifdef ASSOC_HOST_TEST
 return mock_backoff_random;
#else
 return nrf_802154_random_get();
#endif
}
static void cca_schedule(uint32_t now){tx.cca_due_us=now+(cca_random()&((1u<<tx.cca_be)-1u))*CCA_UNIT_US;tx.state=6;}

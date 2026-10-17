"""Offline ARM build. No flash, serial, probe, radio or network operations."""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SDK=ROOT.parents[3]/'nrf sdk'
DEFAULT=ROOT.parents[4]/'gcc-arm-none-eabi-7-2018-q2-update-win32/bin'
RADIO=['nrf_802154.c','nrf_802154_core.c','nrf_802154_core_hooks.c','nrf_802154_critical_section.c',
 'nrf_802154_debug.c','nrf_802154_pib.c','nrf_802154_priority_drop_direct.c',
 'nrf_802154_notification_direct.c','nrf_802154_request_direct.c','nrf_802154_rssi.c',
 'nrf_802154_rx_buffer.c','nrf_802154_timer_coord.c','fal/nrf_802154_fal.c',
 'mac_features/nrf_802154_ack_timeout.c','mac_features/nrf_802154_filter.c','mac_features/nrf_802154_frame_parser.c',
 'mac_features/ack_generator/nrf_802154_ack_generator.c',
 'mac_features/ack_generator/nrf_802154_imm_ack_generator.c',
 'mac_features/ack_generator/nrf_802154_enh_ack_generator.c',
 'mac_features/ack_generator/nrf_802154_ack_data.c',
 'rsch/nrf_802154_rsch.c','rsch/nrf_802154_rsch_crit_sect.c','rsch/raal/single_phy/single_phy.c',
 'platform/clock/nrf_802154_clock_sdk.c','platform/hp_timer/nrf_802154_hp_timer.c',
 'platform/lp_timer/nrf_802154_lp_timer_nodrv.c','platform/random/nrf_802154_random_stdlib.c',
 'platform/coex/nrf_802154_wifi_coex_none.c','platform/temperature/nrf_802154_temperature_none.c',
 'timer_scheduler/nrf_802154_timer_sched.c']
SUPPORT=['modules/nrfx/mdk/gcc_startup_nrf52840.S','modules/nrfx/mdk/system_nrf52840.c',
 'components/libraries/usbd/app_usbd.c','components/libraries/usbd/class/cdc/acm/app_usbd_cdc_acm.c',
 'components/libraries/usbd/app_usbd_core.c','components/libraries/usbd/app_usbd_serial_num.c',
 'components/libraries/usbd/app_usbd_string_desc.c','components/libraries/util/app_util_platform.c',
 'components/libraries/util/app_error.c','components/libraries/util/app_error_handler_gcc.c',
 'components/libraries/util/app_error_weak.c','components/libraries/util/nrf_assert.c',
 'components/libraries/atomic/nrf_atomic.c','components/libraries/atomic_fifo/nrf_atfifo.c','integration/nrfx/legacy/nrf_drv_clock.c',
 'integration/nrfx/legacy/nrf_drv_power.c','modules/nrfx/drivers/src/nrfx_clock.c',
 'modules/nrfx/drivers/src/nrfx_power.c','modules/nrfx/drivers/src/nrfx_usbd.c','modules/nrfx/drivers/src/nrfx_systick.c',
 'modules/nrfx/drivers/src/prs/nrfx_prs.c','modules/nrfx/soc/nrfx_atomic.c']
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--gcc-root',type=Path,default=DEFAULT);args=ap.parse_args()
    output=ROOT/'build';output.mkdir(exist_ok=True)
    gcc=args.gcc_root/'arm-none-eabi-gcc.exe'
    original_make=(ROOT.parents[1]/'airnanny_v17/pca10059/mbr/armgcc/Makefile').read_text()
    includes=[ROOT/'include',ROOT.parent/'raw_radio_v7_assoc_poll_cca/radio_driver',ROOT.parent/'raw_radio_v7_assoc_poll_cca/radio_driver/fem/none']
    includes+=sorted({p.parent for p in (ROOT.parent/'raw_radio_v7_assoc_poll_cca/radio_driver').rglob('*.h') if 'fem' not in p.parts})
    block=original_make.split('# Include folders common to all targets')[1].split('# Libraries common')[0]
    includes+=[SDK/x for x in re.findall(r'\$\(SDK_ROOT\)/([^\s\\]+)',block) if 'zboss' not in x and '802.15.4' not in x]
    flags=['-std=c11','-Os','-g3','-mcpu=cortex-m4','-mthumb','-mfloat-abi=hard','-mfpu=fpv4-sp-d16',
      '-ffunction-sections','-fdata-sections','-fno-strict-aliasing','-Wall','-Wextra',
      '-DNRF52840_XXAA','-DBOARD_PCA10059','-DMBR_PRESENT','-DDUAL_PAN_GATE',
      '-DCONFIG_GPIO_AS_PINRESET','-DNRF_802154_PROJECT_CONFIG="gate_radio_config.h"']
    flags += ['-I'+str(p) for p in includes]
    sources=[ROOT/'src'/name for name in ['main.c','assoc.c','assoc_protocol.c','permit_binding.c','key_gate.c','commission.c','commission_protocol.c','assoc_filter.c','gate_events.c']]
    sources += [ROOT.parent/'raw_radio_v7_assoc_poll_cca/radio_driver'/p for p in RADIO]+[SDK/p for p in SUPPORT]
    objects=[];commands=[]
    with (output/'compile.log').open('w') as log:
        for n,source in enumerate(sources):
            obj=output/(str(n)+'_'+source.stem+'.o');objects.append(obj)
            command=[str(gcc)]+flags+['-c',str(source),'-o',str(obj)]
            commands.append(dict(source=str(source),arguments=command))
            result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True)
            log.write(result.stdout);log.flush()
            if result.returncode: print(result.stdout);raise SystemExit(result.returncode)
        elf=output/'airnanny_ctx1_commission_v7.elf';mapfile=output/'airnanny_ctx1_commission_v7.map'
        link=[str(gcc)]+flags[:10]+[str(o) for o in objects]+['-T'+str(ROOT/'include/gate.ld'),'-L'+str(SDK/'modules/nrfx/mdk'),
          '-Wl,--gc-sections','-Wl,-Map='+str(mapfile),'--specs=nano.specs','--specs=nosys.specs','-o',str(elf)]
        result=subprocess.run(link,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True)
        log.write(result.stdout)
        if result.returncode:print(result.stdout);raise SystemExit(result.returncode)
    hexfile=output/'airnanny_ctx1_commission_v7.hex'
    subprocess.run([str(args.gcc_root/'arm-none-eabi-objcopy.exe'),'-O','ihex',str(elf),str(hexfile)],check=True)
    size=subprocess.check_output([str(args.gcc_root/'arm-none-eabi-size.exe'),str(elf)],universal_newlines=True)
    version=subprocess.check_output([str(gcc),'--version'],universal_newlines=True).splitlines()[0]
    manifest=dict(identity='airnanny_ctx1_commission_v7',software_only=True,flashed=False,
      compiler=version,target='nRF52840 PCA10059 MBR, app at 0x1000',size_output=size,
      hex_sha256=hashlib.sha256(hexfile.read_bytes()).hexdigest().upper(),map=mapfile.name,
      locally_compiled_radio_sources=RADIO,sdk_support_sources=SUPPORT,
      link_command=link,compile_commands=commands,
      input_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest().upper() for p in sources+list((ROOT/'include').glob('*'))})
    (ROOT/'evidence/build_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print(version);print(size);print('HEX SHA256',manifest['hex_sha256']);print('NOT FLASHED')
if __name__=='__main__':main()

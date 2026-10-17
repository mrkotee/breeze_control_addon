"""Offline ARM build for the V26 dual-PAN runtime.

No flash, serial, probe, radio or network operations. Produces an ELF, a HEX, a
map and evidence/build_manifest.json, and nothing else.

Ported from ctx1_rx_admission_v25/tools/build.py. Two changes beyond the source
list and the output name:

  * the toolchain is located rather than assumed, so the same script runs with
    the operator's Windows GCC and with a Linux GCC of the same version. The
    manifest records which one produced the image.

  * the manifest states, in the image's own evidence, whether this build is
    bit-comparable with the V17 to V25 lineage. A Linux xPack GCC of the same
    version, date and branch revision links a different bundled newlib, so its
    image is functionally equivalent and byte-different; a V25 reproduction
    measured text +568 and bss +12. See
    ../evidence/dual_pan_build_toolchain.json.

Usage:
    python3 tools/build.py --gcc-root /path/to/arm-gcc/bin
"""
import argparse, hashlib, json, platform, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT.parents[3] / 'nrf sdk'
IDENTITY = 'airnanny_dual_pan_runtime_v29'

# The lineage's compiler, for the bit-comparability statement in the manifest.
LINEAGE_COMPILER_FRAGMENT = 'GNU Tools for Arm Embedded Processors 7-2018-q2-update'

RADIO = ['nrf_802154.c', 'nrf_802154_core.c', 'nrf_802154_core_hooks.c', 'nrf_802154_critical_section.c',
 'nrf_802154_debug.c', 'nrf_802154_pib.c', 'nrf_802154_priority_drop_direct.c',
 'nrf_802154_notification_direct.c', 'nrf_802154_request_direct.c', 'nrf_802154_rssi.c',
 'nrf_802154_rx_buffer.c', 'nrf_802154_timer_coord.c', 'fal/nrf_802154_fal.c',
 'mac_features/nrf_802154_ack_timeout.c', 'mac_features/nrf_802154_filter.c',
 'mac_features/nrf_802154_frame_parser.c',
 'mac_features/ack_generator/nrf_802154_ack_generator.c',
 'mac_features/ack_generator/nrf_802154_imm_ack_generator.c',
 'mac_features/ack_generator/nrf_802154_enh_ack_generator.c',
 'mac_features/ack_generator/nrf_802154_ack_data.c',
 'rsch/nrf_802154_rsch.c', 'rsch/nrf_802154_rsch_crit_sect.c', 'rsch/raal/single_phy/single_phy.c',
 'platform/clock/nrf_802154_clock_sdk.c', 'platform/hp_timer/nrf_802154_hp_timer.c',
 'platform/lp_timer/nrf_802154_lp_timer_nodrv.c', 'platform/random/nrf_802154_random_stdlib.c',
 'platform/coex/nrf_802154_wifi_coex_none.c', 'platform/temperature/nrf_802154_temperature_none.c',
 'timer_scheduler/nrf_802154_timer_sched.c']

SUPPORT = ['modules/nrfx/mdk/gcc_startup_nrf52840.S', 'modules/nrfx/mdk/system_nrf52840.c',
 'components/libraries/usbd/app_usbd.c', 'components/libraries/usbd/class/cdc/acm/app_usbd_cdc_acm.c',
 'components/libraries/usbd/app_usbd_core.c', 'components/libraries/usbd/app_usbd_serial_num.c',
 'components/libraries/usbd/app_usbd_string_desc.c', 'components/libraries/util/app_util_platform.c',
 'components/libraries/util/app_error.c', 'components/libraries/util/app_error_handler_gcc.c',
 'components/libraries/util/app_error_weak.c', 'components/libraries/util/nrf_assert.c',
 'components/libraries/atomic/nrf_atomic.c', 'components/libraries/atomic_fifo/nrf_atfifo.c',
 'integration/nrfx/legacy/nrf_drv_clock.c',
 'integration/nrfx/legacy/nrf_drv_power.c', 'modules/nrfx/drivers/src/nrfx_clock.c',
 'modules/nrfx/drivers/src/nrfx_power.c', 'modules/nrfx/drivers/src/nrfx_usbd.c',
 'modules/nrfx/drivers/src/nrfx_systick.c',
 'modules/nrfx/drivers/src/prs/nrfx_prs.c', 'modules/nrfx/soc/nrfx_atomic.c']

# V25's own translation units, plus the dual-PAN layer. dual_sched.c and
# dual_records.c are compiled in although main.c does not call them yet; the
# linker's --gc-sections drops what is unreferenced, and the next step wires
# them in. assoc_filter.c likewise stays: the patched driver hook now calls
# dual_admit_part, so its predicate is unreferenced in the image and dropped,
# but the host-test harnesses still link it.
OWN = ['main.c', 'assoc.c', 'assoc_protocol.c', 'permit_binding.c', 'key_gate.c',
       'rejoin_transport.c', 'assoc_filter.c', 'gate_events.c',
       'dual_context.c', 'dual_admit.c', 'dual_identity.c', 'dual_sched.c', 'dual_records.c']


def label(path: Path) -> str:
    """Repository-relative where possible, so the manifest stays meaningful on
    another machine; SDK inputs are recorded relative to the recorded SDK root.
    An absolute build path pins evidence to one checkout and one host."""
    for base, prefix in ((ROOT, ''), (SDK, 'nrf sdk/')):
        try:
            return prefix + path.relative_to(base).as_posix()
        except ValueError:
            continue
    return str(path)


def tool(root: Path, name: str) -> Path:
    """Locates a toolchain binary without assuming the host operating system."""
    for candidate in (root / name, root / (name + '.exe')):
        if candidate.exists():
            return candidate
    raise SystemExit('missing toolchain binary: %s in %s' % (name, root))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gcc-root', type=Path, required=True,
                    help='directory holding arm-none-eabi-gcc (or .exe)')
    args = ap.parse_args()

    gcc = tool(args.gcc_root, 'arm-none-eabi-gcc')
    objcopy = tool(args.gcc_root, 'arm-none-eabi-objcopy')
    size_tool = tool(args.gcc_root, 'arm-none-eabi-size')

    output = ROOT / 'build'
    output.mkdir(exist_ok=True)

    original_make = (ROOT.parents[1] / 'airnanny_v17/pca10059/mbr/armgcc/Makefile').read_text()
    includes = [ROOT / 'include', ROOT / 'radio_driver', ROOT / 'radio_driver/fem/none']
    includes += sorted({p.parent for p in (ROOT / 'radio_driver').rglob('*.h') if 'fem' not in p.parts})
    block = original_make.split('# Include folders common to all targets')[1].split('# Libraries common')[0]
    includes += [SDK / x for x in re.findall(r'\$\(SDK_ROOT\)/([^\s\\]+)', block)
                 if 'zboss' not in x and '802.15.4' not in x]

    flags = ['-std=c11', '-Os', '-g3', '-mcpu=cortex-m4', '-mthumb', '-mfloat-abi=hard', '-mfpu=fpv4-sp-d16',
      '-ffunction-sections', '-fdata-sections', '-fno-strict-aliasing', '-Wall', '-Wextra',
      '-DNRF52840_XXAA', '-DBOARD_PCA10059', '-DMBR_PRESENT', '-DDUAL_PAN_GATE',
      '-DCONFIG_GPIO_AS_PINRESET', '-DNRF_802154_PROJECT_CONFIG="gate_radio_config.h"']
    flags += ['-I' + str(p) for p in includes]

    sources = [ROOT / 'src' / name for name in OWN]
    sources += [ROOT / 'radio_driver' / p for p in RADIO] + [SDK / p for p in SUPPORT]

    objects, commands = [], []
    own_headers = sorted((ROOT / 'include').glob('*.h')) + sorted((ROOT / 'src').glob('*.inc'))
    with (output / 'compile.log').open('a') as log:
        for n, source in enumerate(sources):
            obj = output / (str(n) + '_' + source.stem + '.o')
            objects.append(obj)
            command = [str(gcc)] + flags + ['-c', str(source), '-o', str(obj)]
            commands.append(dict(source=str(source), arguments=command))
            # Incremental: reuse an object only when it is newer than its source
            # and newer than every header this target owns. Compiling this tree
            # over a mounted filesystem is slow enough that a full rebuild does
            # not fit one bounded invocation.
            if obj.exists() and obj.stat().st_mtime >= max(
                    [source.stat().st_mtime] + [h.stat().st_mtime for h in own_headers]):
                continue
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    universal_newlines=True)
            log.write(result.stdout); log.flush()
            if result.returncode:
                print(result.stdout); raise SystemExit(result.returncode)

        elf = output / (IDENTITY + '.elf')
        mapfile = output / (IDENTITY + '.map')
        link = [str(gcc)] + flags[:10] + [str(o) for o in objects] + \
            ['-T' + str(ROOT / 'include/gate.ld'), '-L' + str(SDK / 'modules/nrfx/mdk'),
             '-Wl,--gc-sections', '-Wl,-Map=' + str(mapfile),
             '--specs=nano.specs', '--specs=nosys.specs', '-o', str(elf)]
        result = subprocess.run(link, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True)
        log.write(result.stdout)
        if result.returncode:
            print(result.stdout); raise SystemExit(result.returncode)

    hexfile = output / (IDENTITY + '.hex')
    subprocess.run([str(objcopy), '-O', 'ihex', str(elf), str(hexfile)], check=True)
    size = subprocess.check_output([str(size_tool), str(elf)], universal_newlines=True)
    version = subprocess.check_output([str(gcc), '--version'], universal_newlines=True).splitlines()[0]

    lineage = LINEAGE_COMPILER_FRAGMENT in version
    manifest = dict(
        identity=IDENTITY, software_only=True, flashed=False,
        compiler=version, build_host=platform.system(),
        target='nRF52840 PCA10059 MBR, app at 0x1000',
        size_output=size,
        hex_sha256=hashlib.sha256(hexfile.read_bytes()).hexdigest().upper(),
        map=mapfile.name,
        bit_comparable_with_v17_to_v25_lineage=lineage,
        toolchain_note=(
            'built with the lineage toolchain; the image is bit-comparable with V17..V25'
            if lineage else
            'built with a GCC of the same version, date and branch revision as the lineage but a '
            'different distribution, whose bundled newlib differs. The image is functionally '
            'equivalent and NOT bit-comparable with V17..V25; a V25 reproduction measured '
            'text +568 and bss +12. See ../evidence/dual_pan_build_toolchain.json. Run this '
            'script with the operator Windows toolchain to obtain a lineage-identical image.'),
        locally_compiled_radio_sources=RADIO, sdk_support_sources=SUPPORT, own_sources=OWN,
        link_command=link, compile_commands=commands,
        sdk_root=str(SDK),
        input_sha256={label(p): hashlib.sha256(p.read_bytes()).hexdigest().upper()
                      for p in sources + sorted((ROOT / 'include').glob('*'))
                      + sorted((ROOT / 'src').glob('*.inc'))})
    (ROOT / 'evidence/build_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n',
                                                       encoding='utf-8')
    print(version)
    print('build host:', platform.system())
    print(size)
    print('HEX SHA256', manifest['hex_sha256'])
    print('bit-comparable with V17..V25 lineage:', lineage)
    print('NOT FLASHED')


if __name__ == '__main__':
    main()

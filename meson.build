project('mebuki', 'c',
  version : '0.1.0',
  meson_version : '>=1.10.0',
  default_options : ['c_std=c23', 'buildtype=minsize']
)

objcopy = find_program('objcopy')
objdump = find_program('objdump')
rfp_cli = find_program('rfp-cli')
python_exe = find_program('python3', 'python', required: true)

serial_port_option = get_option('serial_port')

bearssl_dep = dependency(
    'bearssl',
    fallback: ['bearssl', 'bearssl_dep'],
)

app_common_sources = files(
  'src/uart.c',
  'src/system.c',
  'src/br_sha256.c',
  'src/test_rsip.c',
  'src/test_flash.c',
)

app_sources = files(
  'src/main.c',
  'src/startup.c',
)
app_crt_sources = files(
  'src/crt/main.c',
  'src/crt/startup.c',
  'src/crt/retarget.c',
)
app_includes = include_directories('src')

vendor_sources = files(
  'vendor/rsip_ecdsa_p256_sha256.c',
  'vendor/flash_type1.c',
)
vendor_includes = include_directories('vendor')
machine_linker = files('src/flash.ld')

app_exe = executable(
  'app',
  [app_sources, app_common_sources, vendor_sources],
  include_directories: [app_includes, vendor_includes],
  dependencies: [ bearssl_dep ],
  link_args: [
    '-nostdlib',
    '-T' + machine_linker[0].full_path(),
    '-Wl,--print-map-locals,-Map=' + meson.current_build_dir() / 'app.map',
  ],
  link_depends: machine_linker,
  name_suffix: 'elf',
)

machine_linker_crt = files('src/crt/flash.ld')
app_crt_exe = executable(
  'app_crt',
  [app_crt_sources, app_common_sources, vendor_sources],
  include_directories: [app_includes, vendor_includes],
  dependencies: [ bearssl_dep ],
  link_args: [
    '-T' + machine_linker_crt[0].full_path(),
    '-Wl,--print-map-locals,-Map=' + meson.current_build_dir() / 'app_crt.map',
  ],
  link_depends: machine_linker_crt,
  name_suffix: 'elf',
)

app_hex = custom_target(
  'app_hex',
  input: app_exe,
  output: app_exe.name() + '.s32',
  command: [objcopy, '-O', 'srec', '@INPUT@', '@OUTPUT@'],
  build_by_default: true,
)

app_crt_hex = custom_target(
  'app_crt_hex',
  input: app_crt_exe,
  output: app_crt_exe.name() + '.s32',
  command: [objcopy, '-O', 'srec', '@INPUT@', '@OUTPUT@'],
  build_by_default: true,
)

app_txt = custom_target(
  'app_txt',
  input: app_exe,
  output: app_exe.name() + '.txt',
  command: [objdump, '-d', '-S', '-l', '@INPUT@'],
  capture : true,
  build_by_default: true,
)

app_crt_txt = custom_target(
  'app_crt_txt',
  input: app_crt_exe,
  output: app_crt_exe.name() + '.txt',
  command: [objdump, '-d', '-S', '-l', '@INPUT@'],
  capture : true,
  build_by_default: true,
)

run_target(
  'deploy',
  command: [
    rfp_cli,
    '-d', 'RX200',
    '-t', 'e2l',
    '-if', 'fine',
    '-a',
    app_hex,
  ]
)

run_target(
  'deploy_crt',
  command: [
    rfp_cli,
    '-d', 'RX200',
    '-t', 'e2l',
    '-if', 'fine',
    '-a',
    app_crt_hex,
  ]
)

if serial_port_option == ''
  error('serial_port option must be specified. Use -Dserial_port=<port>')
endif

run_script = meson.current_source_dir() / 'scripts' / 'run.py'

run_target(
  'run',
  command: [
    python_exe,
    run_script,
    serial_port_option,
    '--build-dir', meson.current_build_dir(),
    '--rfp-cli', rfp_cli,
    '--display',
  ]
)

run_target(
  'run-capture',
  command: [
    python_exe,
    run_script,
    serial_port_option,
    '--build-dir', meson.current_build_dir(),
    '--rfp-cli', rfp_cli,
  ]
)

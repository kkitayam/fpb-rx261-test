project('mebuki', 'c',
  version : '0.1.0',
  meson_version : '>=1.10.0',
  default_options : ['c_std=c23', 'buildtype=minsize']
)

objcopy = find_program('objcopy')
objdump = find_program('objdump')
rfp_cli = find_program('rfp-cli')

bearssl_dep = dependency(
    'bearssl',
    fallback: ['bearssl', 'bearssl_dep'],
)

app_sources = files(
  'src/main.c',
  'src/uart.c',
  'src/system.c',
  'src/startup.c',
  'src/br_sha256.c',
)
app_includes = include_directories('src')

vendor_sources = files(
  'vendor/rsip_ecdsa_p256_sha256.c',
)
vendor_includes = include_directories('vendor')

machine_linker_file = files('src/flash.ld')
machine_linker = meson.current_source_dir() / 'src/flash.ld'

app_exe = executable(
  'app',
  [app_sources, vendor_sources],
  include_directories: [app_includes, vendor_includes],
  dependencies: [ bearssl_dep ],
  link_args: [
    '-T' + machine_linker,
    '-Wl,--print-map-locals,-Map=' + meson.current_build_dir() / 'app.map',
  ],
  link_depends: machine_linker_file,
  name_suffix: 'elf',
)

app_hex = custom_target(
  'app_hex',
  input: app_exe,
  output: app_exe.name() + '.s32',
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
  'run',
  command: [
    rfp_cli,
    '-d', 'RX200',
    '-t', 'e2l',
    '-if', 'fine',
    '-run',
  ]
)

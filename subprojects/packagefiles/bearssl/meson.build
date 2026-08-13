project('bearssl', 'c',
  version: '0.6',
  meson_version: '>=1.10.0'
)

bearssl_inc = include_directories('inc', 'src')

bearssl_codec_sources = files(
  'src/codec/ccopy.c',
  'src/codec/dec32be.c',
  'src/codec/dec32le.c',
  'src/codec/enc32be.c',
  'src/codec/enc32le.c',
)

bearssl_hash_sources = files(
  'src/hash/sha2small.c',
)

bearssl_int_sources = files(
  'src/int/i31_add.c',
  'src/int/i31_bitlen.c',
  'src/int/i31_decmod.c',
  'src/int/i31_decode.c',
  'src/int/i31_decred.c',
  'src/int/i31_encode.c',
  'src/int/i31_fmont.c',
  'src/int/i31_iszero.c',
  'src/int/i31_moddiv.c',
  'src/int/i31_modpow.c',
  'src/int/i31_modpow2.c',
  'src/int/i31_montmul.c',
  'src/int/i31_mulacc.c',
  'src/int/i31_muladd.c',
  'src/int/i31_ninv31.c',
  'src/int/i31_reduce.c',
  'src/int/i31_rshift.c',
  'src/int/i31_sub.c',
  'src/int/i31_tmont.c',
  'src/int/i32_div32.c',
)

bearssl_ec_sources = files(
  'src/ec/ec_p256_m31.c',
  'src/ec/ec_secp256r1.c',
  'src/ec/ec_secp384r1.c',
  'src/ec/ec_secp521r1.c',
  'src/ec/ecdsa_i31_bits.c',
  'src/ec/ecdsa_i31_vrfy_raw.c',
)

bearssl_sources = bearssl_codec_sources + bearssl_hash_sources + bearssl_int_sources + bearssl_ec_sources

bearssl_dep = declare_dependency(
  sources: bearssl_sources,
  include_directories: bearssl_inc,
)

if meson.is_subproject()
  meson.override_dependency('bearssl', bearssl_dep)
endif

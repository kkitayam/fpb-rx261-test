#ifndef RX261_CORE_H
#define RX261_CORE_H

/* see https://llvm-gcc-renesas.com/migration-guides/rx/index.html */

#include <stdint.h>

/* Control register indices which can be used with __MVFC and __MVTC */
#define PSW          0x0
#define PC           0x1
#define USP          0x2
#define FPSW         0x3
#define BPSW         0x8
#define BPC          0x9
#define ISP          0xA
#define FINTV        0xB
#define INTB         0xC
#define EXTB         0xD

/* Intrinsic functions */
#define __BRK()               __builtin_rx_brk()
#define __CLRPSW(x)           __builtin_rx_clrpsw(x)
#define __INT(x)              __builtin_rx_int(x)
#define __MACHI(x,y)          __builtin_rx_machi(x,y)
#define __MACHI_A1(x,y)       __builtin_rx_machi_A1(x,y)
#define __MACLO(x,y)          __builtin_rx_maclo(x,y)
#define __MACLO_A1(x,y)       __builtin_rx_maclo_A1(x,y)
#define __MULHI(x,y)          __builtin_rx_mulhi(x,y)
#define __MULHI_A1(x,y)       __builtin_rx_mulhi_A1(x,y)
#define __MULLO(x,y)          __builtin_rx_mullo(x,y)
#define __MULLO_A1(x,y)       __builtin_rx_mullo_A1(x,y)
#define __MVFACHI()           __builtin_rx_mvfachi()
#define __MVFACMI()           __builtin_rx_mvfacmi()
#define __MVFC(x)             __builtin_rx_mvfc(x)
#define __MVTACHI(x)          __builtin_rx_mvtachi(x)
#define __MVTACHI_A1(x)       __builtin_rx_mvtachi_A1(x)
#define __MVTACLO(x)          __builtin_rx_mvtaclo(x)
#define __MVTACLO_A1(x)       __builtin_rx_mvtaclo_A1(x)
#define __MVTC(reg, val)      __builtin_rx_mvtc(reg, val)
#define __MVTIPL(x)           __builtin_rx_mvtipl(x)
#define __RACW(x)             __builtin_rx_racw(x)
#define __RACW_A1(x)          __builtin_rx_racw_A1(x)
#define __REVL(x)             __builtin_bswap32(x)
#define __REVW(x)             __builtin_rx_revw(x)
#define __RMPA8(w,x,y,z)      __builtin_rx_rmpa(w,x,y,z)
#define __RMPA16(w,x,y,z )    __builtin_rx_rmpa(w,x,y,z)
#define __RMPA32(w,x,y,z )    __builtin_rx_rmpa(w,x,y,z)
#define __ROUND(x)            __builtin_rx_round(x)
#define __DROUND(x)           __builtin_rx_dround(x)
#define __SETPSW(x)           __builtin_rx_setpsw(x)
#define __WAIT()              __builtin_rx_wait()
#define __XCHG(x, y)          __builtin_rx_xchg(x, y)
#define __BSET(x, y)          __builtin_rx_bset(x, y)
#define __BCLR(x, y)          __builtin_rx_bclr(x, y)
#define __BNOT(x, y)          __builtin_rx_bnot(x, y)
#define __BSET_MEM(x, y)      __builtin_rx_bset_mem(x, y)
#define __BCLR_MEM(x, y)      __builtin_rx_bclr_mem(x, y)
#define __BNOT_MEM(x, y)      __builtin_rx_bnot_mem(x, y)
#define __EMULA_A0(x, y)      __builtin_rx_emula_A0(x, y)
#define __EMULA_A1(x, y)      __builtin_rx_emula_A1(x, y)
#define __EMACA_A0(x, y)      __builtin_rx_emaca_A0(x, y)
#define __EMACA_A1(x, y)      __builtin_rx_emaca_A1(x, y)
#define __EMSBA_A0(x, y)      __builtin_rx_emsba_A0(x, y)
#define __EMSBA_A1(x, y)      __builtin_rx_emsba_A1(x, y)
#define __MULLH_A0(x, y)      __builtin_rx_mullh_A0(x, y)
#define __MULLH_A1(x, y)      __builtin_rx_mullh_A1(x, y)
#define __MACLH_A0(x, y)      __builtin_rx_maclh_A0(x, y)
#define __MACLH_A1(x, y)      __builtin_rx_maclh_A1(x, y)
#define __MSBLH_A0(x, y)      __builtin_rx_msblh_A0(x, y)
#define __MSBLH_A1(x, y)      __builtin_rx_msblh_A1(x, y)
#define __MSBHI_A0(x, y)      __builtin_rx_msbhi_A0(x, y)
#define __MSBHI_A1(x, y)      __builtin_rx_msbhi_A1(x, y)
#define __MSBLO_A0(x, y)      __builtin_rx_msblo_A0(x, y)
#define __MSBLO_A1(x, y)      __builtin_rx_msblo_A1(x, y)
#define __RDACW_A0(x)         __builtin_rx_rdacw_A0(x)
#define __RDACW_A1(x)         __builtin_rx_rdacw_A1(x)
#define __RDACL_A0(x)         __builtin_rx_rdacl_A0(x)
#define __RDACL_A1(x)         __builtin_rx_rdacl_A1(x)
#define __RACL_A0(x)          __builtin_rx_racl_A0(x)
#define __RACL_A1(x)          __builtin_rx_racl_A1(x)
#define __MVFACHI_A0(x)       __builtin_rx_mvfachi_A0(x)
#define __MVFACHI_A1(x)       __builtin_rx_mvfachi_A1(x)
#define __MVFACMI_A0(x)       __builtin_rx_mvfacmi_A0(x)
#define __MVFACMI_A1(x)       __builtin_rx_mvfacmi_A1(x)
#define __MVFACLO_A0(x)       __builtin_rx_mvfaclo_A0(x)
#define __MVFACGU_A0(x)       __builtin_rx_mvfacgu_A0(x)
#define __MVFACGU_A1(x)       __builtin_rx_mvfacgu_A1(x)
#define __MVTACGU_A0(x)       __builtin_rx_mvtacgu_A0(x)
#define __MVTACGU_A1(x)       __builtin_rx_mvtacgu_A1(x)
#define __SAVE(x)             __builtin_rx_save(x)
#define __RSTR(x)             __builtin_rx_rstr(x)
#define __MVFDC(x)            __builtin_rx_mvfdc(x)
#define __MVTDC(x, y)         __builtin_rx_mvtdc(x, y)
#define __MVFDR()             __builtin_rx_mvfdr()
#define __BFMOV(dest, src, slsb, dlsb, width) __builtin_rx_bfmov(dest, src, slsb, dlsb, width)
#define __BFMOVZ(dest, src, slsb, dlsb, width) __builtin_rx_bfmovz(dest, src, slsb, dlsb, width)
#define __INIT_TFU() __init_tfu()
#define __SINCOSF(value, sin, cos) __builtin_rx_sincosf(value, sin, cos)
#define __ATAN2HYPOTF(y, x, atan2, hypot) __builtin_rx_atan2hypotf(y, x, atan2, hypot)
#define __SINF(value)        __builtin_rx_sinf(value)
#define __COSF(value)        __builtin_rx_cosf(value)
#define __ATAN2F(y, x)       __builtin_rx_atan2f(y, x)
#define __HYPOTF(x, y)       __builtin_rx_hypotf(x, y)
    
#endif /* RX261_CORE_H */

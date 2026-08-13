#include "rx261_core.h"
#include <stddef.h>

/* Symbols defined by the linker script */
extern const uint8_t _isp_top[];
extern const uint8_t _usp_top[];
extern const uint8_t _text_load[];
extern uint8_t _text[];
extern uint8_t _etext[];

extern void system_init(void) __attribute__((section(".text.reset")));
extern int main(void);
extern void *memcpy(void*,const void*,size_t);

void Reset_Handler(void) __attribute__((section(".text.reset"),noinline));

void Reset_Handler(void)
{
    __MVTC(ISP, (uintptr_t)_isp_top);
    __MVTC(USP, (uintptr_t)_usp_top);
    system_init();
    if ((uintptr_t)_text != (uintptr_t)_text_load) {
        memcpy(_text, _text_load, _etext - _text);
    }
    main();
END:
    __WAIT();
    goto END;
}

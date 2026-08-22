MEMORY
{
	RAM  : ORIGIN = 0x4,        LENGTH = 0x1fffc
	DROM : ORIGIN = 0x00100000, LENGTH = 0x2000
	PROM : ORIGIN = 0xFFF80000, LENGTH = 0x80000
}

ISP_SIZE = 2K;
USP_SIZE = 4K;
BOOT_SIZE = 32K;

BOOT_ORIGIN = ORIGIN(PROM) + LENGTH(PROM) - BOOT_SIZE;
VECTOR_BASE = 0xFFFFFF80;

__isp_top   = ORIGIN(RAM) + LENGTH(RAM);
__isp_limit = __isp_top - ISP_SIZE;
__usp_top   = __isp_limit;
__usp_limit = __usp_top - USP_SIZE;

PROVIDE(_PrivilegedInst_Handler = 0xFFFFFFFF);
PROVIDE(_Access_Handler         = 0xFFFFFFFF);
PROVIDE(_UndefinedInst_Handler  = 0xFFFFFFFF);
PROVIDE(_FloatingPoint_Handler  = 0xFFFFFFFF);
PROVIDE(_NMI_Handler            = 0xFFFFFFFF);

ENTRY(_Reset_Handler)

SECTIONS
{
	. = ORIGIN(RAM);
	.text.ram ALIGN(4) :
	{
		__text = .;
		*(.text.flash_type1_pe_ram)
		. = ALIGN(4);
		__etext = .;
	} > RAM AT > PROM = 0xFF
	__text_load = LOADADDR(.text.ram);

	. = ORIGIN(PROM) + SIZEOF(.text.ram);
	.text ALIGN(4) :
	{
		*(.text) *(.text.*)
		. = ALIGN(4);
	} > PROM = 0xFF
/*
	.exception_vector ALIGN(4) :
	{
		LONG(_PrivilegedInst_Handler)
		LONG(_Access_Handler)
		. += 4;
		LONG(_UndefinedInst_Handler)
		. += 4;
		LONG(_FloatingPoint_Handler)
		. += 16;
		LONG(_NMI_Handler)
		LONG(_Reset_Handler)
	} > PROM = 0xFF
	__ext_base = ORIGIN(.exception_vector) - 0x50;

	.interrupt_vector ALIGN(4) :
	{
		*(.interrupt_vector) *(.interrupt_vector.*)
	} > PROM = 0xFF
	__int_base = ORIGIN(.interrupt_vector);
*/
	.rodata ALIGN(4) :
	{
		*(.rodata) *(.rodata.*)
		. = ALIGN(4);
		__erodata = .;
	} > PROM = 0xFF

	.eh_frame ALIGN(4) :
	{
		*(.eh_frame)
		*(.eh_frame.*)
		. = ALIGN(4);
	} > PROM = 0xFF

	/*
	 * Legacy initialization/finalization sections.
	 */
	.init ALIGN(4) :
	{
		KEEP(*(.init))
		. = ALIGN(4);
	} > PROM = 0xFF

	.fini ALIGN(4) :
	{
		KEEP(*(.fini))
		. = ALIGN(4);
	} > PROM = 0xFF

	/*
	 * C/C++ initialization arrays.
	 */
	.preinit_array ALIGN(4) :
	{
		PROVIDE_HIDDEN(__preinit_array_start = .);
		KEEP(*(.preinit_array))
		KEEP(*(.preinit_array.*))
		PROVIDE_HIDDEN(__preinit_array_end = .);
		. = ALIGN(4);
	} > PROM = 0xFF

	.init_array ALIGN(4) :
	{
		PROVIDE_HIDDEN(__init_array_start = .);
		KEEP(*(SORT(.init_array.*)))
		KEEP(*(.init_array))
		PROVIDE_HIDDEN(__init_array_end = .);
		. = ALIGN(4);
	} > PROM = 0xFF

	.fini_array ALIGN(4) :
	{
		PROVIDE_HIDDEN(__fini_array_start = .);
		KEEP(*(SORT(.fini_array.*)))
		KEEP(*(.fini_array))
		PROVIDE_HIDDEN(__fini_array_end = .);
		. = ALIGN(4);
	} > PROM = 0xFF

	. = ORIGIN(RAM) + SIZEOF(.text.ram);
	.data ALIGN(4) :
	{
		__data = .;
		*(.data) *(.data.*)
		*(.sdata) *(.sdata.*)
		. = ALIGN(4);
		__edata = .;
	} > RAM AT > PROM = 0xFF
	__data_load = LOADADDR(.data);

	.bss ALIGN(4) (NOLOAD) :
	{
		__bss = .;
		*(.bss) *(.bss.*)
		*(.sbss) *(.sbss.*)
		*(COMMON)
		. = ALIGN(4);
		__ebss = .;
		__end = .;
	} > RAM

	__heap_start = ALIGN(__end,4);

	.mde VECTOR_BASE + 0x0:
	{
		KEEP(*(.mde))
	} > PROM = 0xFF
	.ofs1 VECTOR_BASE + 0x8:
	{
		KEEP(*(.ofs1))
	} > PROM = 0xFF
	.ofs0 VECTOR_BASE + 0xC:
	{
		KEEP(*(.ofs0))
	} > PROM = 0xFF
	.fixed_vector VECTOR_BASE + 0x50:
	{
		LONG(_PrivilegedInst_Handler) /* 0xFFFFFFD0 */
		LONG(_Access_Handler)         /* 0xFFFFFFD4 */
		. += 4;                       /* 0xFFFFFFD8 */
		LONG(_UndefinedInst_Handler)  /* 0xFFFFFFDC */
		. += 4;                       /* 0xFFFFFFE0 */
		LONG(_FloatingPoint_Handler)  /* 0xFFFFFFE4 */
		. += 16;                      /* 0xFFFFFFE8 - 0xFFFFFFF4 */
		LONG(_NMI_Handler)            /* 0xFFFFFFF8 */
		LONG(_Reset_Handler)          /* 0xFFFFFFFC */
	} > PROM = 0xFF
}

ASSERT(__usp_limit >= __ebss, "RAM overflow");

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
	.reset BOOT_ORIGIN :
	{
		. = ALIGN(4);
		*(.text.reset)
		*(.text.system_init)
		. = ALIGN(4);
	} > PROM = 0xFF

	.text ALIGN(4) :
	{
		__text = .;
		*(.text) *(.text.*)
		. = ALIGN(4);
		__etext = .;
	} > PROM = 0xFF
	__text_load = LOADADDR(.text);

	.rodata ALIGN(4) :
	{
		*(.rodata) *(.rodata.*)
		. = ALIGN(4);
		__erodata = .;
	} > PROM = 0xFF

	. = ORIGIN(RAM);
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
		_bss = .;
		*(.bss) *(.bss.*)
		*(.sbss) *(.sbss.*)
		*(COMMON)
		. = ALIGN(4);
		_ebss = .;
		_end = .;
	} > RAM

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

ASSERT(LOADADDR(.data) + SIZEOF(.data) <= VECTOR_BASE, "Boot image overlaps fixed vectors");
ASSERT(__usp_limit >= _ebss, "RAM overflow");
ASSERT(SIZEOF(.data) == 0, "Initialized global/static variables are forbidden in the bootloader.");

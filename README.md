# fpb-rx261-test

Experiments for running mebuki on the Renesas FPB-RX261 board.

This repository contains experimental code used to investigate the RX261 flash memory and RSIP hardware accelerator. The goal is to establish the platform support required to run mebuki on RX261 devices.

## Purpose

The project is used to:

* Evaluate RX261 code flash operations.
* Evaluate RX261 RSIP functionality.
* Validate software components required by mebuki.
* Develop low-level platform code for RX261.
* Measure and verify hardware behavior before integration into mebuki.

This repository is intended for experimentation and prototyping. It is not intended to be used as a production firmware project.

## Hardware

* Renesas FPB-RX261 (Fast Prototyping Board for RX261)

## Toolchain

* GNURX
* Meson

## Requirements

* Renesas FPB-RX261
* E2 Lite debugger (on-board)
* Renesas Flash Programmer CLI (`rfp_cli`)
* GNURX toolchain
* Meson

## Features

Current experiments include:

* Code flash access
* SRAM execution during flash operations
* RSIP-based ECDSA-P256-SHA256 verification
* SHA-256 calculation using BearSSL
* UART logging
* Firmware deployment using `rfp_cli`
* Automated target reset and execution

## Build

Build the firmware image.

```sh
meson setup build --cross-file cross/rx-elf-gcc.ini
meson compile -C build
```

## Deploy

Program the firmware image to the target board.

The `deploy` target uses Renesas Flash Programmer CLI (`rfp_cli`) and the on-board E2 Lite debugger on the FPB-RX261 board.

```sh
meson compile -C build deploy
```

## Run

Reset and start the target board.

The `run` target uses `rfp_cli` to reset the device and release it from reset.

```sh
meson compile -C build run
```

## Repository layout

```text
.
├── cross/
│   └── rx-elf-gcc.ini          Meson cross file
├── src/
│   ├── startup.c              Startup code
│   ├── system.c               Clock and system initialization
│   ├── uart.c                 UART driver
│   ├── test_flash.c           Flash experiments
│   ├── test_rsip.c            RSIP experiments
│   └── ...
├── subprojects/
│   └── bearssl                BearSSL dependency
├── vendor/
│   ├── hal_flash.c            Flash support code
│   ├── rsip_ecdsa_p256_sha256.c
│   └── ...
└── meson.build
```

## Relationship to mebuki

This repository is a preparatory project for integrating RX261 support into mebuki.

The experiments performed here help validate the flash and cryptographic functionality required by mebuki before integration work begins.

Related project:

* https://github.com/kkitayam/mebuki

## Notes

* Flash operations may erase existing data.
* Test code may change without notice.
* Hardware configuration is specific to FPB-RX261.
* Results obtained here may be incorporated into mebuki in the future.

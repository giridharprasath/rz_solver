# rz_solver

## Overview
`rz_solver` is a Rizin plugin that provides a simple interface to an SMT solver, currently supporting ROP (Return-Oriented Programming) constraint solving using RzIL APIs.

## Installation

1. Configure the build using Meson:
    ```sh
    meson --buildtype=debug --prefix=/usr/ buildDir/
    ```
   Use `--prefix` to specify Rizin library directories.

2. Compile and install the plugin:
    ```sh
    ninja -C buildDir/ install
    ```

## Usage

### ROP Example

1. Load the binary and analyze for ROP gadget info:
    ```sh
    rizin -N binary
    [0x00401000]> /Rg
    ```

2. Solve ROP constraints:
    ```sh
    [0x00401000]> /Rs
    Usage: /Rs[?] <Gadget constraints>   # ROP Gadget solver help
    ```
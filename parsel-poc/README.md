## PARseL Proof-of-Concept

This folder contains PARsel proof-of-concept prototype, which we used for our evaluation in the paper. 

## Environment and Language

Here we list out the environment (OS, processor) and programming language used at the time of development.

  - OS: Ubuntu 18.04 LTS
  - CPU: Intel i7-3770
  - Language: C++
  - To be deployed on: [iMX6-SabreLite](https://docs.sel4.systems/Hardware/sabreLite.html) 

## Installation, Build, and Simulation

There are two ways to build this prototype: (1) Manually install all the [dependencies](https://docs.sel4.systems/GettingStarted) (sel4 kernel, user libraries, etc.) and write a configuration to build an image for running it on SabreLite, or (2) Automatically install and generate a configuration file via [sel4 tutorials build platform](https://github.com/seL4/sel4-tutorials-manifest); however, it still requires some manual changes to the config files.
The latter option is quicker and we describe it below. We are working on the former option for the final e2e release.

1. Make a new directory and cd to it.
2. Follow the tutorials setup instructions [here](https://docs.sel4.systems/Tutorials/). In particular, run instructions for  *Prerequisites* and *Get the code* under *The Tutorials*. At the end of this step, you will have sel4 tutorials downloaded and setup.
3. Replace `projects/sel4-tutorials/common.py` with this repo's `config-related-files/common.py` and `projects/sel4-tutorials/settings.cmake` with this repo's `config-related-files/settings.cmake`. These changes include `sabre` platform config support in both files. (For more details, check out `PLAT_CONFIG` in common.py and `elseif(${TUT_BOARD} STREQUAL "imx6")` in settings.cmake).
4. Now, run the following, which should generate a new `hello-world` [tutorial](https://docs.sel4.systems/Tutorials/hello-world.html). However under the name `parsel` and `parsel_build`. 
```
$ mkdir parsel
$ cd parsel
$ ../init --plat sabre --tut hello-world
$ cd ../parsel_build
$ ninja
```
5. Delete `./parsel/src` folder and `./parsel/CMakeLists.txt` file; and add this repo's `src/` folder and `CMakeLists.txt` to `./parsel`. This is where we modify the exisiting hello-world tutorial configuration to build PARseL prototype.
6. Change `KernelArmExportPMUUser:BOOL=OFF` to `KernelArmExportPMUUser:BOOL=ON` in `./parsel_build/CMakeCache.txt`. This is to enable benchmarking APIs for printing performance results.
7. Run the following:
```
$ cd parsel_build
$ ninja
$ ./simulate
```
One of benefits of this tutorial configurations is it gives a `./simulate` file to simulate the SabreLite prototype on QEMU. Running `./simulate` should print all the debug messages RP, PSMT, SP, and UPs print. It also prints the evaluation results.

To exit QEMU: press: `Ctrl + a`, and then `x`.

## Running it on SabreLite hardware

After building the prototype as mentioned above, you should find an image at `./parsel_build/images/hello-world-image-arm-imx6`. This image contains our prototype. Now, to run it on SabreLite:

1. Ensure you have U-Boot bootloader on your SabreLite device. If not, checkout this [page](https://docs.sel4.systems/Hardware/sabreLite.html). Ensure you have a microSD to load the image from.
2. Manually copy `hello-world-image-arm-imx6` to microSD.
3. Try to boot SabreLite. Interrupt the auto boot using spacebar, then type the following:
```
=> mmc dev 0
=> fatload mmc 0 ${loadaddr} hello-world-image-arm-imx6
=> bootelf ${loadaddr}
```
This should boot up PARseL image and run and print the same as the simulation on QEMU. 

WARNING: In some cases, MMC driver might pick up the image from dev 1 of the microSD. In that case, try:
```
=> mmc dev 1
=> fatload mmc 1 ${loadaddr} hello-world-image-arm-imx6
=> bootelf ${loadaddr}
```

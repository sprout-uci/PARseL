## PARseL Proofs

This folder contains PARsel runtime signing function proofs. 

### Installation of Project Everst (for F\*, KaRaMeL, and HACL\*)
Follow the intruction of [https://project-everest.github.io/](https://project-everest.github.io/).
To be inclusive, we provide the necessary installation steps (as of May 2023) below:

**Prerequisite (for Windows only):** Open up a Cygwin64 terminal with a Cygwin git client. The Project Everest library is a native Windows DLL but they rely on Cygwin to provide the Unix tools that many of our projects rely on.

First, clone the repository:
```
git clone https://github.com/project-everest/everest
cd everest
```
To check the environment, run the following and install if anything missed:
```
./everest check
```
Build all the projects together by running:
```
./everest make
```
and test the generated binaries with:
```
./everest test
```
Whenever you want to revert to a clean state, run:
```
./everest clean
```

### Installation of seL4 libraries


### PARseL Set-up
Move the `lowToC` directory into the `everest/FStar/examples/lowToC` and build our code via
```
cd FStar/examples/lowToC
make
```
It will generate a verified C code using KaRaMeL. 
To clean-up, run (in the same path):
```
make clean
```
# PARseL: Towards a Verified Root-of-Trust over seL4 Microkernel

[STILL UNDER CONSTRUCTION]

This repository contains a working and verified proof-of-concept for [*PARseL: Towards a Verified Root-of-Trust over seL4 Microkernel*](https://arxiv.org/pdf/2308.11921.pdf). 
However, we have not yet released a fully integrated end-to-end prototype for PARseL on seL4, and therefore, we emphasize that this code base is currently intended solely as an experimental research prototype.

## PARseL Overview

Widespread adoption and growing popularity of embedded/IoT/CPS devices make them attractive attack targets. 
On low-to-mid-range devices, security features are typically few or none due to various constraints. 
Such devices are thus subject to malware-based compromise. 
One popular defensive measure is Remote Attestation (RA) which allows a trusted entity to determine the current software integrity of an untrusted remote device.
For higher-end devices, RA is achievable via secure hardware components. 
For low-end (bare metal) devices, minimalistic hybrid (hardware/-software) RA is effective, which incurs some hardware modifications.
That leaves certain mid-range devices (e.g., ARM Cortex-A family) equipped with standard hardware components, e.g., a memory management unit (MMU) and perhaps a secure boot facility. 
In this space, seL4 (a verified microkernel with guaranteed process isolation) is a promising platform for attaining RA. 
HYDRA [1] made a first step towards this, albeit without achieving any verifiability or provable guarantees.
This paper picks up where HYDRA left off by constructing a PARseL architecture, that separates all user-dependent components from the TCB.
This leads to much stronger isolation guarantees, based on seL4 alone, and facilitates formal verification. 
In PARseL, we use formal verification to obtain several security properties for the isolated RA TCB, including: memory safety, functional correctness, and secret independence. 
We implement PARseL in F* and specify/prove expected properties using Hoare logic. 
Next, we automatically translate the F* implementation to C using KaRaMeL, which preserves verified properties of PARseL C implementation (atop seL4). 
Finally, we instantiate and evaluate PARseL on a commodity platform – a SabreLite embedded device.

## PARseL Implementation

This repository has two sub-directories: `parsel-poc` and `parsel-proofs`. 
Each sub-directory includes a readme file for installing and running the proof-of-concept and proofs. 
`parsel-poc` contains the prototype for PARseL attestation implemented in C, run over seL4, and deployed on Sabrelite.
`parsel-proofs` contains the prototype for PARseL attestation implemented in Low*, verified in F*, and translated to C using Karamel. 
Translated C code from `parsel-proofs` is not integrated with `parsel-poc` yet, because both build procedures and dependencies are different.
However, `parsel-poc` contains the exact same logic as translated C code from `parsel-proofs`, but it's directly implemented in C.

include(${SEL4_TUTORIALS_DIR}/settings.cmake)
sel4_tutorials_regenerate_tutorial(${CMAKE_CURRENT_SOURCE_DIR})

cmake_minimum_required(VERSION 3.7.2)

project(hello-world C ASM)

sel4_tutorials_setup_roottask_tutorial_environment()


add_executable(attestation src/attestation.c src/hacl-c/Hacl_HMAC_SHA2_256.c src/hacl-c/Hacl_SHA2_256.c src/hacl-c/Hacl_Ed25519.c src/hacl-c/FStar.c)
target_link_libraries(attestation sel4tutorials sel4bench)

add_executable(process1 src/process1.c)
target_link_libraries(process1 sel4tutorials sel4bench)

add_executable(process2 src/process2.c)
target_link_libraries(process2 sel4tutorials sel4bench)

add_executable(process3 src/process3.c)
target_link_libraries(process3 sel4tutorials sel4bench)

add_executable(initial_process src/initial_process.c)
target_link_libraries(initial_process 
        sel4runtime sel4 muslc utils sel4tutorials
		sel4allocman sel4muslcsys sel4platsupport sel4utils sel4debug sel4bench)

include(cpio)

MakeCPIO(archive.o "$<TARGET_FILE:attestation>;$<TARGET_FILE:initial_process>;$<TARGET_FILE:process1>;$<TARGET_FILE:process2>;$<TARGET_FILE:process3>")
MakeCPIO(archive_main.o "$<TARGET_FILE:attestation>")

add_executable(main src/main.c archive_main.o src/hacl-c/Hacl_HMAC_SHA2_256.c src/hacl-c/Hacl_SHA2_256.c src/hacl-c/Hacl_Ed25519.c src/hacl-c/FStar.c)
target_link_libraries(main sel4tutorials sel4allocman sel4utils sel4bench)

add_executable(hello-world src/main.c archive.o src/hacl-c/Hacl_HMAC_SHA2_256.c src/hacl-c/Hacl_SHA2_256.c src/hacl-c/Hacl_Ed25519.c src/hacl-c/FStar.c)
target_link_libraries(hello-world
    sel4
    muslc utils sel4tutorials
    sel4muslcsys sel4platsupport sel4utils sel4debug sel4allocman sel4bench)

include(rootserver)
DeclareRootserver(hello-world)

set(FINISH_COMPLETION_TEXT "
RP: Experiments done!\n")

set(START_COMPLETION_TEXT "
	Unexpected response from root thread.")
configure_file(${SEL4_TUTORIALS_DIR}/tools/expect.py ${CMAKE_BINARY_DIR}/check @ONLY)
include(simulation)
GenerateSimulateScript()

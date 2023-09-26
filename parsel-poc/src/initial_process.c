
/*
 * Initial User Process. This communicates with RP (Process Spawner & Measurement Thread) 
 * to spawn user processes: process1, process2, process3.
 */ 

#include <autoconf.h>

#include <stdio.h>
#include <assert.h>

#include <sel4/sel4.h>

#include <simple/simple.h>
#include <simple-default/simple-default.h>

#include <vka/object.h>

#include <allocman/allocman.h>
#include <allocman/bootstrap.h>
#include <allocman/vka.h>

#include <vspace/vspace.h>

#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>

#include <utils/arith.h>
#include <utils/zf_log.h>
#include <sel4utils/sel4_zf_logif.h>

#include <sel4platsupport/bootinfo.h>

#include <unistd.h>

#define NUMBER_PROCESSES 1


int spawn(seL4_Word processId, seL4_CPtr ep) {

  seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 1);
  seL4_Word msg_to_ProcessSpawner = processId;
  seL4_SetMR(0, msg_to_ProcessSpawner);
  printf("IP: Sent process spawning request for process%d using badge %lu.\n", (uint32_t)processId, ep);
  tag = seL4_Call(ep, tag);

  ZF_LOGF_IF(seL4_MessageInfo_get_length(tag) != 1,
          "Length of the data send from root thread was not what was expected.\n"
          "\tHow many registers did you set with seL4_SetMR, within the root thread?\n");

  seL4_Word msg_from_ProcessSpawner = seL4_GetMR(0);
  printf("IP: msg from ProcessSpwaner: %x, msg to ProcessSpwaner: %x\n", msg_from_ProcessSpawner, msg_to_ProcessSpawner);

  if (msg_from_ProcessSpawner == 0x0) return 0;
  return 1;
}

int main(int argc, char **argv) {

  printf("IP: hey, I'm born!\n"); 

  ZF_LOGF_IF(argc < 1, "Missing arguments.\n");
  seL4_CPtr ep = (seL4_CPtr) atol(argv[0]);

  printf("IP: Initiating user process spawning.\n");

  for (int i = 0; i < NUMBER_PROCESSES; i++) {
    int error = spawn(0x1 + i, ep);
    if (error == 1) {
      printf("IP: IPC to ProcessSpwaner failed.\n");
    }
  }

  spawn(0x0, ep);

  printf("IP: Spawned all the user processes. Exiting.\n");
  return 0;
}

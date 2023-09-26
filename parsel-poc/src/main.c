
/*
 * Main Root Process (RP). This runs just after sel4 boot.
 * It also implements Process Spawner & Measurement Thread (PSMT).
 */


#include <autoconf.h>

#include <stdio.h>
#include <assert.h>

#include <elf/elf.h>
#include <cpio/cpio.h>

#include <sel4/sel4.h>
#include <sel4runtime.h>
#include <sel4runtime/gen_config.h>

#include <simple/simple.h>
#include <simple-default/simple-default.h>

#include <vka/object.h>
#include <vka/object_capops.h>

#include <allocman/allocman.h>
#include <allocman/bootstrap.h>
#include <allocman/vka.h>

#include <vspace/vspace.h>

#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>
#include <sel4bench/sel4bench.h>

#include <utils/arith.h>
#include <utils/zf_log.h>
#include <sel4utils/sel4_zf_logif.h>

#include <sel4platsupport/bootinfo.h>
#include <time.h>
#include <unistd.h>


#define HMAC_OUTPUT_LEN 32
extern void Hacl_SHA2_256_hash(uint8_t *hash1, uint8_t *input, uint32_t len);


/* cpio set up in the build system */
extern char _cpio_archive[];
extern char _cpio_archive_end[];

/* constants */
#define EP_SP_BADGE 0x28 // arbitrary (but unique) number for SP's endpoint badge
#define EP_IUP_BADGE 0x18 // arbitrary (but unique) number for IUP's endpoint badge
#define EP_PS_BADGE 0x19 // arbitrary (but unique) number for PSMT's endpoint badge
#define EP_UP_BADGE 0x38 // arbitrary (but unique) number for UP's endpoint badge

#define SP_PRIORITY seL4_MaxPrio
#define SP_IMAGE_NAME "attestation" // SP

#define IUP_PRIORITY seL4_MaxPrio
#define IUP_IMAGE_NAME "initial_process" // IUP

#define P1_PRIORITY seL4_MaxPrio
#define P1_IMAGE_NAME "process1" // P1

#define IPCBUF_FRAME_SIZE_BITS 12 // use a 4K frame for the IPC buffer
#define IPCBUF_VADDR 0x7000000 // arbitrary (but free) address for IPC buffer

/* global environment variables */
seL4_BootInfo *info;
simple_t simple;
vka_t vka;
allocman_t *allocman;
vspace_t vspace;
seL4_CPtr pd_cap;
seL4_CPtr cspace_cap;

#define PAGE_SIZE (1 << seL4_PageBits)

/* static memory for the allocator to bootstrap with */
#define ALLOCATOR_STATIC_POOL_SIZE (BIT(seL4_PageBits) * 10000)
UNUSED static char allocator_mem_pool[ALLOCATOR_STATIC_POOL_SIZE];

/* dimensions of virtual memory for the allocator to use */
#define ALLOCATOR_VIRTUAL_POOL_SIZE (BIT(seL4_PageBits) * 10000)

/* static memory for virtual memory bootstrapping */
UNUSED static sel4utils_alloc_data_t data_memory;


/* Proces Spawner */
vka_object_t ep_object_ProcessSpawner;
cspacepath_t ep_cap_path_ProcessSpawner;
static char tls_region_ProcessSpawner[CONFIG_SEL4RUNTIME_STATIC_TLS] = {};
#define THREAD_STACK_SIZE 512
UNUSED static int thread_ProcessSpawner_stack[THREAD_STACK_SIZE];
const int stack_alignment_requirement = sizeof(seL4_Word);

/* initial process */
sel4utils_process_t initial_process;
cspacepath_t ep_cap_path_ip;

/* new process */
#define MAX_USER_PROCESSES 5
sel4utils_process_t user_processes[MAX_USER_PROCESSES];
cspacepath_t ep_cap_path_ups[MAX_USER_PROCESSES];
int user_process_counter = 0;
uint8_t *measurementMap[MAX_USER_PROCESSES];

/* Signing process */
sel4utils_process_t att_process;
cspacepath_t ep_cap_path_ap;
cspacepath_t ep_cap_path_ap_up;



//////////////////////////////////////////////////////
/* Process Spawner Thread 
	1. Spawns Initial Process (IUP) that user configures 
	to spawn other user processes.
	2. Spawns user processes as requested by IUP.
	3. While spawning the user processes it records
	their measurement.
	4. Spawns Signing Process (SP) and sends the 
	measurements to it via IPC.
*/
////////////////////////////////////////

void thread_ProcessSpawner(void){
	printf("ProcessSpawner: Hi!\n");
	UNUSED int error = 0;

	vspace_t vspace_ProcessSpawner;
	sel4utils_alloc_data_t data_ProcessSpawner;
	error = sel4utils_bootstrap_vspace_with_bootinfo_leaky(&vspace_ProcessSpawner, &data_ProcessSpawner, pd_cap, &vka, info);

	printf("ProcessSpawner: Hi!\n");

	void *vaddr;
	UNUSED reservation_t virtual_reservation;
	virtual_reservation = vspace_reserve_range(&vspace_ProcessSpawner,
                                             ALLOCATOR_VIRTUAL_POOL_SIZE, seL4_AllRights, 1, &vaddr);
	ZF_LOGF_IF(virtual_reservation.res == NULL, "Failed to reserve a chunk of memory.\n");
	printf("ProcessSpawner: vaddr %p\n", vaddr);
	printf("ProcessSpawner: Created a fresh chunk of virtual pool\n");


	/* Create and spawn SP */

	sel4utils_process_config_t config_SP = process_config_default_simple(&simple, SP_IMAGE_NAME, SP_PRIORITY);

	error = sel4utils_configure_process_custom(&att_process, &vka, &vspace_ProcessSpawner, config_SP);
	ZF_LOGF_IFERR(error, "Failed to spawn a new thread.\n"
				"\tsel4utils_configure_process expands an ELF file into our VSpace.\n"
				"\tBe sure you've properly configured a VSpace manager using sel4utils_bootstrap_vspace_with_bootinfo.\n"
				"\tBe sure you've passed the correct component name for the new thread!\n");

	NAME_THREAD(att_process.thread.tcb.cptr, SP_IMAGE_NAME);

	vka_object_t ep_object_ap = {0};
	error = vka_alloc_endpoint(&vka, &ep_object_ap);
	ZF_LOGF_IFERR(error, "Failed to allocate new endpoint object.\n");

	printf("ProcessSpawner: Created an end point badge for Att to talk to us\n");

	seL4_CPtr ep_cap_ap = 0;
	vka_cspace_make_path(&vka, ep_object_ap.cptr, &ep_cap_path_ap);

	ep_cap_ap = sel4utils_mint_cap_to_process(&att_process, ep_cap_path_ap,
											seL4_AllRights, EP_SP_BADGE);

	ZF_LOGF_IF(ep_cap_ap == 0, "Failed to mint a badged copy of the IPC endpoint into the new thread's CSpace.\n"
			"\tsel4utils_mint_cap_to_process takes a cspacepath_t: double check what you passed.\n");

	printf("ProcessSpawner: att process ep cap slot: %lu.\n", ep_cap_path_ap.capPtr);
	printf("ProcessSpawner: att process ep cap: %lu.\n", ep_cap_ap);

	vka_object_t ep_object_ap_up = {0};
	error = vka_alloc_endpoint(&vka, &ep_object_ap_up);
	ZF_LOGF_IFERR(error, "Failed to allocate new endpoint object.\n");

	printf("ProcessSpawner: Created an end point badge for Att to talk to us\n");

	seL4_CPtr ep_cap_ap_up = 0;
	vka_cspace_make_path(&vka, ep_object_ap_up.cptr, &ep_cap_path_ap_up);

	ep_cap_ap_up = sel4utils_mint_cap_to_process(&att_process, ep_cap_path_ap_up,
											seL4_AllRights, EP_SP_BADGE + 1);

	ZF_LOGF_IF(ep_cap_ap_up == 0, "Failed to mint a badged copy of the IPC endpoint into the new thread's CSpace.\n"
			"\tsel4utils_mint_cap_to_process takes a cspacepath_t: double check what you passed.\n");

	printf("ProcessSpawner: att process new ep cap slot: %lu.\n", ep_cap_path_ap_up.capPtr);
	printf("ProcessSpawner: att process new ep cap: %lu.\n", ep_cap_ap_up);

	seL4_Word argc_SP = 2;
	char string_args_SP[argc_SP][WORD_STRING_SIZE];
	char* argv_SP[argc_SP];
	sel4utils_create_word_args(string_args_SP, argv_SP, argc_SP, ep_cap_ap, ep_cap_ap_up);

	error = sel4utils_spawn_process_v(&att_process, &vka, &vspace_ProcessSpawner, argc_SP, (char**) &argv_SP, 1);
	ZF_LOGF_IFERR(error, "Failed to spawn and start the new thread.\n"
			"\tVerify: the new thread is being executed in the root thread's VSpace.\n"
			"\tIn this case, the CSpaces are different, but the VSpaces are the same.\n"
			"\tDouble check your vspace_t argument.\n");

	printf("ProcessSpawner: Gave birth to att process. \n");


	/* Create and spawn IUP */

	sel4utils_process_config_t config_IUP = process_config_default_simple(&simple, IUP_IMAGE_NAME, IUP_PRIORITY);
	printf("ProcessSpawner: Creating the initial process (IUP)\n");
	error = sel4utils_configure_process_custom(&initial_process, &vka, &vspace_ProcessSpawner, config_IUP);
	ZF_LOGF_IFERR(error, "Failed to spawn a new thread.\n"
                "\tsel4utils_configure_process expands an ELF file into our VSpace.\n"
                "\tBe sure you've properly configured a VSpace manager using sel4utils_bootstrap_vspace_with_bootinfo.\n"
                "\tBe sure you've passed the correct component name for the new thread!\n");

	printf("ProcessSpawner: IUP spawned\n");
	NAME_THREAD(initial_process.thread.tcb.cptr, "ProcessSpawner_IUP");

	vka_object_t ep_object_ip = {0};
	error = vka_alloc_endpoint(&vka, &ep_object_ip);
	ZF_LOGF_IFERR(error, "Failed to allocate new endpoint object.\n");

	printf("ProcessSpawner: Created an end point badge for IUP to talk to ProcessSpawner\n");

	seL4_CPtr ep_cap_ip = 0;
	vka_cspace_make_path(&vka, ep_object_ip.cptr, &ep_cap_path_ip);

	ep_cap_ip = sel4utils_mint_cap_to_process(&initial_process, ep_cap_path_ip,
                                            seL4_AllRights, EP_IUP_BADGE);

	ZF_LOGF_IF(ep_cap_ip == 0, "Failed to mint a badged copy of the IPC endpoint into the new thread's CSpace.\n"
             "\tsel4utils_mint_cap_to_process takes a cspacepath_t: double check what you passed.\n");

	printf("ProcessSpawner: ip process ep cap slot: %lu.\n", ep_cap_path_ip.capPtr);
	printf("ProcessSpawner: ip process ep cap: %lu.\n", ep_cap_ip);

	seL4_Word argc_IUP = 1;
	char string_args_IUP[argc_IUP][WORD_STRING_SIZE];
	char* argv_IUP[argc_IUP];
	sel4utils_create_word_args(string_args_IUP, argv_IUP, argc_IUP, ep_cap_ip);

	error = sel4utils_spawn_process_v(&initial_process, &vka, &vspace_ProcessSpawner, argc_IUP, (char**) &argv_IUP, 1);
	ZF_LOGF_IFERR(error, "Failed to spawn and start the new thread.\n"
			"\tVerify: the new thread is being executed in the root thread's VSpace.\n"
			"\tIn this case, the CSpaces are different, but the VSpaces are the same.\n"
			"\tDouble check your vspace_t argument.\n");

	printf("ProcessSpawner: Spawned IUP. \n");

	/* Create and spawn UPs as requested by IUP */
	while(1) {

		/* Send and receive msgs with IUP through IPC */
		seL4_Word sender_badge_ip = 0;
		seL4_MessageInfo_t tag_ip = seL4_MessageInfo_new(0, 0, 0, 0);
		seL4_Word msg_ip;

		// receive UP spawning request from IUP
		tag_ip = seL4_Recv(ep_cap_path_ip.capPtr, &sender_badge_ip);
		ZF_LOGF_IF(sender_badge_ip != EP_IUP_BADGE,
				"The badge we received from the new thread didn't match our expectation.\n");

		ZF_LOGF_IF(seL4_MessageInfo_get_length(tag_ip) != 1,
				"Response data from the new process was not the length expected.\n"
				"\tHow many registers did you set with seL4_SetMR within the new process?\n");

		// get Id of the UP to be spawned
		msg_ip = seL4_GetMR(0);
		printf("ProcessSpawner: got a message %#" PRIxPTR " from IUP through badge %#" PRIxPTR "\n", msg_ip, sender_badge_ip);

		char image_name[12] = {0};
		uint8_t image_prio = seL4_MaxPrio;
		if (msg_ip > 0x0 && user_process_counter < MAX_USER_PROCESSES) {
			char id[4] = {0};
			sprintf(id, "%x", msg_ip);
			strncpy(image_name, "process", 7);
			strcat(image_name, id);
			printf("ProcessSpawner: Request received to create a new process %s.\n", image_name);

			unsigned long start2 = sel4bench_get_cycle_count();
			
			// start spawning UP
			sel4utils_process_config_t config = process_config_default_simple(&simple, image_name, image_prio);

			sel4utils_process_t user_process;
			cspacepath_t ep_cap_path_up;

			error = sel4utils_configure_process_custom(&user_process, &vka, &vspace_ProcessSpawner, config);
			ZF_LOGF_IFERR(error, "Failed to spawn a new thread.\n"
						"\tsel4utils_configure_process expands an ELF file into our VSpace.\n"
						"\tBe sure you've properly configured a VSpace manager using sel4utils_bootstrap_vspace_with_bootinfo.\n"
						"\tBe sure you've passed the correct component name for the new thread!\n");

			NAME_THREAD(user_process.thread.tcb.cptr, image_name);

			unsigned long size;
        	unsigned long cpio_len = _cpio_archive_end - _cpio_archive;
        	char *file = cpio_get_file(_cpio_archive, cpio_len, image_name, &size);

			// Measure the binary of UP before loading
			unsigned long start1 = sel4bench_get_cycle_count();
			uint8_t *digest = malloc(32);
			Hacl_SHA2_256_hash((uint8_t*)digest, (uint8_t*)file, (uint32_t)size);
			unsigned long end1 = sel4bench_get_cycle_count();
			printf("ProcessSpawner: TIME TAKEN to measure %lu of UP memory = %lu\n", size, (end1 - start1));

			// Store the measurement in a local buffer
			measurementMap[user_process_counter] = (uint8_t*)malloc(HMAC_OUTPUT_LEN*sizeof(uint8_t));
			memcpy(measurementMap[user_process_counter], digest, HMAC_OUTPUT_LEN);

			free(digest);

			vka_object_t ep_object_up = {0};
			error = vka_alloc_endpoint(&vka, &ep_object_up);
			ZF_LOGF_IFERR(error, "Failed to allocate new endpoint object.\n");

			printf("ProcessSpawner: Created an end point badge for UP%d to talk to us\n", user_process_counter);

			seL4_CPtr ep_cap_up = 0;
			vka_cspace_make_path(&vka, ep_object_up.cptr, &ep_cap_path_up);

			// Assign a unique badge for each UP. This badge is an identifier that is handled by sel4 only.
			// The below 'seL4_AllRights' flag lets UP to freely use the EP to send/receive data.
			// However, this does not mean it can modify the badge number.
			ep_cap_up = sel4utils_mint_cap_to_process(&user_process, ep_cap_path_up,
													seL4_AllRights, EP_UP_BADGE + user_process_counter);
			ZF_LOGF_IF(ep_cap_up == 0, "Failed to mint a badged copy of the IPC endpoint into UP CSpace.\n"
					"\tsel4utils_mint_cap_to_process takes a cspacepath_t: double check what you passed.\n");
			
			// Mint IPC capabilites to UP
			seL4_CPtr ep_cap_up_ap = 0;
			ep_cap_up_ap = sel4utils_mint_cap_to_process(&user_process, ep_cap_path_ap_up,
													seL4_AllRights, EP_UP_BADGE + user_process_counter);

			ZF_LOGF_IF(ep_cap_up_ap == 0, "Failed to mint second badged copy of the IPC endpoint into UP CSpace.\n"
					"\tsel4utils_mint_cap_to_process takes a cspacepath_t: double check what you passed.\n");

			printf("ProcessSpawner: new user process ep cap slot: %" PRIxPTR ".\n", ep_cap_path_up.capPtr);
			printf("ProcessSpawner: new user process ep cap: %#" PRIxPTR ".\n", ep_cap_up);

			seL4_Word argc = 2;
			char string_args[argc][WORD_STRING_SIZE];
			char* argv[argc];

			// Send EP capabilities to UP via arguments
			sel4utils_create_word_args(string_args, argv, argc, ep_cap_up, ep_cap_up_ap);

			printf("ProcessSpawner: Sent %lu as argument 1\n", ep_cap_up);
    		printf("ProcessSpawner: Sent %lu as argument 2\n", ep_cap_up_ap);

			// Spawn UP
			error = sel4utils_spawn_process_v(&user_process, &vka, &vspace_ProcessSpawner, argc, (char**) &argv, 1);
			ZF_LOGF_IFERR(error, "Failed to spawn and start the new thread.\n"
					"\tVerify: the new thread is being executed in the root thread's VSpace.\n"
					"\tIn this case, the CSpaces are different, but the VSpaces are the same.\n"
					"\tDouble check your vspace_t argument.\n");

			printf("ProcessSpawner: Gave birth to UP %d. \n", user_process_counter);

			unsigned long end2 = sel4bench_get_cycle_count();
			printf("ProcessSpawner: TIME TAKEN to spawn UP = %lu\n", (end2 - start2));

			user_processes[user_process_counter] = user_process;
			ep_cap_path_ups[user_process_counter] = ep_cap_path_up;
			user_process_counter++;
		}
		else if (msg_ip == 0x0) {
			// reply ack to IUP
			seL4_SetMR(0, 0);
			seL4_Reply(tag_ip);

			unsigned long start3 = sel4bench_get_cycle_count();
				
			printf("ProcessSpawner: Sending measurements to SP. \n");

			// Send all the measurements to SP
			for (int i=0; i < user_process_counter; i++){
				seL4_MessageInfo_t tag_SP = seL4_MessageInfo_new(0, 0, 0, 8);

				seL4_Word measurement[8];
				memcpy(measurement, measurementMap[i], 32);
				seL4_SetMR(0, measurement[0]);
				seL4_SetMR(1, measurement[1]);
				seL4_SetMR(2, measurement[2]);
				seL4_SetMR(3, measurement[3]);
				seL4_SetMR(4, measurement[4]);
				seL4_SetMR(5, measurement[5]);
				seL4_SetMR(6, measurement[6]);
				seL4_SetMR(7, measurement[7]);
				
				seL4_Call(ep_cap_path_ap.capPtr, tag_SP);
			}

			seL4_MessageInfo_t close_tag_SP = seL4_MessageInfo_new(0, 0, 0, 1);

			seL4_SetMR(0, 0);
			seL4_Call(ep_cap_path_ap.capPtr, close_tag_SP);
			printf("ProcessSpawner: Sent all measurements to SP. \n");

			unsigned long end3 = sel4bench_get_cycle_count();
			printf("ProcessSpawner: TIME TAKEN to send all measurements to SP = %lu\n", (end3 - start3));
			break;
		}

		// reply ack to IUP
		seL4_SetMR(0, 0);
		seL4_Reply(tag_ip);
	}

	for (int i=0; i < user_process_counter; i++){
		free(measurementMap[i]);
	}

	// The below lets RP know PSMT is done.
	seL4_Word sender_badge_rp = 0;
	UNUSED seL4_MessageInfo_t tag_rp;
	seL4_Word msg_rp = 0;

	tag_rp = seL4_Recv(ep_object_ProcessSpawner.cptr, &sender_badge_rp);

	ZF_LOGF_IF(seL4_MessageInfo_get_length(tag_rp) != 1,
				"Length of the data send from root thread was not what was expected.\n"
				"\tHow many registers did you set with seL4_SetMR, within the root thread?\n");

	msg_rp = seL4_GetMR(0);
	printf("ProcessSpawner: got a message %#" PRIxPTR " from RP\n", msg_rp);

	seL4_SetMR(0, 0);
	printf("ProcessSpawner: replying ack to RP\n");
	seL4_Reply(tag_rp);

	printf("ProcessSpawner: Bye! My work is done. \n");
  	return;
}


//////////////////////////////////////////////
/* main function (root process) starts here */
//////////////////////////////////////////////
int main(void) {

	printf("RP: starting..!\n");

    UNUSED int error = 0;
	sel4bench_init();
	unsigned long start, end1, end2;

	start = sel4bench_get_cycle_count();

	/* get boot info */
	info = platsupport_get_bootinfo();
	ZF_LOGF_IF(info == NULL, "Failed to get bootinfo.");

	/* Set up logging and give us a name: useful for debugging if the thread faults */
	zf_log_set_tag_prefix("RP:");
	NAME_THREAD(seL4_CapInitThreadTCB, "RP");

	/* init simple */
	simple_default_init_bootinfo(&simple, info);
	/* print out bootinfo and other info about simple */
	simple_print(&simple);

	/* create an allocator */
	allocman = bootstrap_use_current_simple(&simple, ALLOCATOR_STATIC_POOL_SIZE, allocator_mem_pool);
	ZF_LOGF_IF(allocman == NULL, "Failed to initialize allocator.\n"
																	"\t Memory pool sufficiently sized?\n"
																	"\t Memory pool pointer valid?\n");

	/* create a vka (interface for interacting with the underlying allocator) */
	allocman_make_vka(&vka, allocman);

	printf("RP: initialized allocman\n");

	/* get cspace root cnode and vspace root page directory */
	cspace_cap = simple_get_cnode(&simple);
	pd_cap = simple_get_pd(&simple);

	/* create a vspace (virtual memory management interface). We pass
	* boot info not because it will use capabilities from it, but so
	* it knows the address and will add it as a reserved region */
	error = sel4utils_bootstrap_vspace_with_bootinfo_leaky(&vspace, &data_memory, pd_cap, &vka, info);
    ZF_LOGF_IFERR(error, "Failed to prepare root thread's VSpace for use.\n"
		              "\tsel4utils_bootstrap_vspace_with_bootinfo reserves important vaddresses.\n"
		              "\tIts failure means we can't safely use our vaddrspace.\n");

	/* fill the allocator with virtual memory */
    void *vaddr;
    UNUSED reservation_t virtual_reservation = vspace_reserve_range(&vspace,
                                               ALLOCATOR_VIRTUAL_POOL_SIZE, seL4_AllRights, 1, &vaddr);
    if (virtual_reservation.res == 0) {
        ZF_LOGF("Failed to provide virtual memory for allocator");
    }

    bootstrap_configure_virtual_pool(allocman, vaddr, ALLOCATOR_VIRTUAL_POOL_SIZE, pd_cap);


	/***** Initialization of thread PSMT *****/
	
	printf("RP: start initializing ProcessSpawner..\n");

	vka_object_t tcb_object_ProcessSpawner = {0};
	error = vka_alloc_tcb(&vka, &tcb_object_ProcessSpawner);
	ZF_LOGF_IFERR(error, "Failed to allocate IUP_Spanwer TCB.\n"
				"\t VKA given sufficient bootstrap memory?\n");

	vka_object_t ipc_frame_object_ProcessSpawner;
	error = vka_alloc_frame(&vka, IPCBUF_FRAME_SIZE_BITS, &ipc_frame_object_ProcessSpawner);
	ZF_LOGF_IFERR(error, "Failed to alloc a frame for the IPC buffer.\n"
							"\tThe frame size is not the number of bytes, but an exponent.\n"
							"\tNB: This frame is not an immediately usable, virtually mapped page.\n")

	seL4_Word ipc_buffer_vaddr_ProcessSpawner = IPCBUF_VADDR;
	error = seL4_ARCH_Page_Map(ipc_frame_object_ProcessSpawner.cptr, pd_cap, 
				ipc_buffer_vaddr_ProcessSpawner, seL4_AllRights, seL4_ARCH_Default_VMAttributes);

	if(error != 0) {

		vka_object_t pt_object_ProcessSpawner;
		error = vka_alloc_page_table(&vka, &pt_object_ProcessSpawner);
		ZF_LOGF_IFERR(error, "Failed to allocate new page table.\n");

		error = seL4_ARCH_PageTable_Map(pt_object_ProcessSpawner.cptr, pd_cap, ipc_buffer_vaddr_ProcessSpawner, seL4_ARCH_Default_VMAttributes);
		ZF_LOGF_IFERR(error, "Failed to map page table into vspace.\n"
								"\tWe are inserting a new page table into the top-level table.\n"
								"\tPass a capability to the new page table, and not for example, the IPC buffer frame vaddr.\n");

		error = seL4_ARCH_Page_Map(ipc_frame_object_ProcessSpawner.cptr, pd_cap, ipc_buffer_vaddr_ProcessSpawner,
									seL4_AllRights, seL4_ARCH_Default_VMAttributes);
		ZF_LOGF_IFERR(error, "Failed again to map the IPC buffer frame into the VSpace.\n"
								"\t(It's not supposed to fail.)\n"
								"\tPass a capability to the IPC buffer's physical frame.\n"
								"\tRevisit the first seL4_ARCH_Page_Map call above and double-check your arguments.\n");
	}

	error = vka_alloc_endpoint(&vka, &ep_object_ProcessSpawner);
	ZF_LOGF_IFERR(error, "Failed to allocate new endpoint object.\n");

	error = vka_mint_object(&vka, &ep_object_ProcessSpawner, &ep_cap_path_ProcessSpawner, seL4_AllRights, EP_PS_BADGE);
	ZF_LOGF_IFERR(error, "Failed to mint new badged copy of IPC endpoint.\n"
							"\tseL4_Mint is the backend for vka_mint_object.\n"
							"\tseL4_Mint is simply being used here to create a badged copy of the same IPC endpoint.\n"
							"\tThink of a badge in this case as an IPC context cookie.\n");

	error = seL4_TCB_Configure(tcb_object_ProcessSpawner.cptr, seL4_CapNull, cspace_cap, seL4_NilData,
								pd_cap, seL4_NilData, ipc_buffer_vaddr_ProcessSpawner, ipc_frame_object_ProcessSpawner.cptr);
	ZF_LOGF_IFERR(error, "Failed to configure the ProcessSpawner TCB object.\n"
							"\tWe're running the ProcessSpawner thread with the root thread's CSpace.\n"
							"\tWe're running the ProcessSpawner thread in the root thread's VSpace.\n"
							"\tWe will not be executing any IPC in this app.\n");

	error = seL4_TCB_SetPriority(tcb_object_ProcessSpawner.cptr, simple_get_tcb(&simple), 255);
	ZF_LOGF_IFERR(error, "Failed to set the priority for the ProcessSpawner TCB object.\n");

	NAME_THREAD(tcb_object_ProcessSpawner.cptr, "RP_ProcessSpawner");

	seL4_UserContext regs_ProcessSpawner = {0};
	size_t regs_size_ProcessSpawner = sizeof(seL4_UserContext) / sizeof(seL4_Word);

	sel4utils_set_instruction_pointer(&regs_ProcessSpawner, (seL4_Word)thread_ProcessSpawner);

	uintptr_t thread_ProcessSpawner_stack_top = (uintptr_t)thread_ProcessSpawner_stack + sizeof(thread_ProcessSpawner_stack);
	ZF_LOGF_IF(thread_ProcessSpawner_stack_top % (stack_alignment_requirement) != 0,
				"Stack top isn't aligned correctly to a %d mod %dB boundary.\n"
				"\tDouble check to ensure you're not trampling.", thread_ProcessSpawner_stack_top, stack_alignment_requirement);

	sel4utils_set_stack_pointer(&regs_ProcessSpawner, thread_ProcessSpawner_stack_top);

	error = seL4_TCB_WriteRegisters(tcb_object_ProcessSpawner.cptr, 0, 0, regs_size_ProcessSpawner, &regs_ProcessSpawner);
	ZF_LOGF_IFERR(error, "Failed to write the ProcessSpawner thread's register set.\n"
							"\tDid you write the correct number of registers? See arg4.\n");

	uintptr_t tls_ProcessSpawner = sel4runtime_write_tls_image(tls_region_ProcessSpawner);
	seL4_IPCBuffer *ipcbuf_ProcessSpawner = (seL4_IPCBuffer*)ipc_buffer_vaddr_ProcessSpawner;
	error = sel4runtime_set_tls_variable(tls_ProcessSpawner, __sel4_ipc_buffer, ipcbuf_ProcessSpawner);
	ZF_LOGF_IF(error, "Failed to set ipc buffer in TLS of new thread");

	error = seL4_TCB_SetTLSBase(tcb_object_ProcessSpawner.cptr, tls_ProcessSpawner);
	ZF_LOGF_IF(error, "Failed to set TLS base");


	/************Spawn PSMT Thread************/

	error = seL4_TCB_Resume(tcb_object_ProcessSpawner.cptr);
	ZF_LOGF_IFERR(error, "Failed to start ProcessSpawner thread.\n");

	end1 = sel4bench_get_cycle_count();
	printf("RP: Total TIME TAKEN for RP = %lu\n", (end1 - start));

	printf("RP: Spawned ProcessSpawner\n");

	// The below code interacts with PSMT, after PSMT done spawning all UP.
	// If this code receives an ack, RP terminates.
	seL4_Word msg_ProcessSpawner = 0;
	seL4_MessageInfo_t tag_ProcessSpawner = seL4_MessageInfo_new(0, 0, 0, 1);

	seL4_SetMR(0, 1);

	tag_ProcessSpawner = seL4_Call(ep_cap_path_ProcessSpawner.capPtr, tag_ProcessSpawner);

	msg_ProcessSpawner = seL4_GetMR(0);
	ZF_LOGF_IF(seL4_MessageInfo_get_length(tag_ProcessSpawner) != 1,
				"Response data from ProcessSpawner was not the length expected.\n"
				"\tHow many registers did you set with seL4_SetMR within thread_2?\n");

	ZF_LOGF_IF(msg_ProcessSpawner != 0,
				"Response data from ProcessSpawner was not what was expected.\n");

	printf("RP: got ack from ProcessSpawner");

	end2 = sel4bench_get_cycle_count();
	printf("RP: Total TIME TAKEN for PSMT = %lu\n", (end2 - end1));
	

	printf("RP: I die here!\n");

	/*  The below code is only required for simulation purposes.
		Because only this process (RP) is connected to the output console.
		Therefore, to see debug print statements while experimentation,
		RP must be blocked/alive until it complete.
		Otherwise RP can be terminated above this point.
	*/
	seL4_MessageInfo_t tag_SP = seL4_MessageInfo_new(0, 0, 0, 1);
	seL4_Word sender_badge_ap = 0;

	tag_SP = seL4_Recv(ep_cap_path_ap.capPtr, &sender_badge_ap);

	sel4bench_destroy();
	printf("RP: Experiments done!\n");

	return 0;
}
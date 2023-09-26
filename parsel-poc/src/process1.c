
/*
 * Sample User Process.  This calls Signing Process for attestation.
 */

#include <stdio.h>

#include <sel4/sel4.h>
#include <sel4utils/process.h>

#include <sel4utils/sel4_zf_logif.h>
#include <sel4bench/sel4bench.h>
#include <time.h>

#include <math.h>



/* constants */
#define CHAL_LEN 32
#define SHA256_OUTPUT_LEN 32

#define HMAC_OUTPUT_LEN 32
#define HMAC_KEY_LEN 32

#define EDDSA_PRIVATE_KEY_LEN 32
#define EDDSA_PUBLIC_KEY_LEN 64
#define EDDSA_SIGNATURE_LEN 64

#define EXP_MAX_ITERATIONS 50



double calculateMean(unsigned long arr[], int size) {
    double sum = 0.0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum / size;
}

double calculateStdDev(unsigned long arr[], int size, double mean) {
    double sum = 0.0;
    for (int i = 0; i < size; i++) {
        double diff = arr[i] - mean;
        sum += diff * diff;
    }
    return sqrt(sum / size);
}


int main(int argc, char **argv) {

		int error;
    unsigned long dtime[EXP_MAX_ITERATIONS] = {0}, start = 0, end = 0;

    printf("P1: hey, I'm born!\n");

    ZF_LOGF_IF(argc < 1, "Missing arguments.\n");
    seL4_CPtr ep = (seL4_CPtr) atol(argv[0]);

    ZF_LOGF_IF(argc < 1, "Missing arguments.\n");
    seL4_CPtr ep_ap = (seL4_CPtr) atol(argv[1]);

    printf("P1: Received %lu as argument 1\n", ep);
    printf("P1: Received %lu as argument 2\n", ep_ap);

    for (int iter = 0; iter < EXP_MAX_ITERATIONS; iter++) {

      seL4_Word chal[CHAL_LEN/sizeof(seL4_Word)];
      memset(chal, iter, CHAL_LEN);

      seL4_Word pk[EDDSA_PUBLIC_KEY_LEN/sizeof(seL4_Word)];
      memset(pk, 0xa, EDDSA_PUBLIC_KEY_LEN);  

      start = sel4bench_get_cycle_count();

      seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 8);
      
      seL4_SetMR(0, chal[0]);
      seL4_SetMR(1, chal[1]);
      seL4_SetMR(2, chal[2]);
      seL4_SetMR(3, chal[3]);
      seL4_SetMR(4, chal[4]);
      seL4_SetMR(5, chal[5]);
      seL4_SetMR(6, chal[6]);
      seL4_SetMR(7, chal[7]);
      printf("P1: Sending chal to AP at %d\n", ep_ap);

      tag = seL4_Call(ep_ap, tag);

      tag = seL4_MessageInfo_new(0, 0, 0, 16);

      seL4_SetMR(0, pk[0]);
      seL4_SetMR(1, pk[1]);
      seL4_SetMR(2, pk[2]);
      seL4_SetMR(3, pk[3]);
      seL4_SetMR(4, pk[4]);
      seL4_SetMR(5, pk[5]);
      seL4_SetMR(6, pk[6]);
      seL4_SetMR(7, pk[7]);
      seL4_SetMR(8, pk[8]);
      seL4_SetMR(9, pk[9]);
      seL4_SetMR(10, pk[10]);
      seL4_SetMR(11, pk[11]);
      seL4_SetMR(12, pk[12]);
      seL4_SetMR(13, pk[13]);
      seL4_SetMR(14, pk[14]);
      seL4_SetMR(15, pk[15]);
      printf("P1: Sending pk to AP at %d\n", ep_ap);
      
      tag = seL4_Call(ep_ap, tag);

      ZF_LOGF_IF(seL4_MessageInfo_get_length(tag) != EDDSA_SIGNATURE_LEN/sizeof(seL4_Word),
                "Length of the data send from root thread was not what was expected.\n"
                "\tHow many registers did you set with seL4_SetMR, within the root thread?\n");

      seL4_Word response[EDDSA_SIGNATURE_LEN/sizeof(seL4_Word)] = {
        seL4_GetMR(0),
        seL4_GetMR(1),
        seL4_GetMR(2),
        seL4_GetMR(3),
        seL4_GetMR(4),
        seL4_GetMR(5),
        seL4_GetMR(6),
        seL4_GetMR(7),
        seL4_GetMR(8),
        seL4_GetMR(9),
        seL4_GetMR(10),
        seL4_GetMR(11),
        seL4_GetMR(12),
        seL4_GetMR(13),
        seL4_GetMR(14),
        seL4_GetMR(15)
        };

      end = sel4bench_get_cycle_count();
      dtime[iter] = end - start;
      printf("P1: TIME TAKEN to attest = %lu\n", dtime[iter]);

      printf("P1: received message from AP - %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x \n", 
          response[0], response[1], response[2], response[3],
          response[4], response[5], response[6], response[7],
          response[8], response[9], response[10], response[11],
          response[12], response[13], response[14], response[15]);

    }

    // The first one is always an outlier for some reason. Just a quick fix.
    dtime[0] = dtime[EXP_MAX_ITERATIONS - 1];

    double mean = calculateMean(dtime, EXP_MAX_ITERATIONS);
    double stdDev = calculateStdDev(dtime, EXP_MAX_ITERATIONS, mean);

    printf("P1: Average TIME TAKEN to attest = %f, %f\n", mean, stdDev);

    printf("P1: Minding my own business! \n");
    while(1);

		printf("P1: time to die! \n");
		return 0;

}

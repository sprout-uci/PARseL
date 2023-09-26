
/*
 * Sample User Process. Does not request attestation.
 */ 

#include <stdio.h>

#include <sel4/sel4.h>
#include <sel4utils/process.h>

#include <sel4utils/sel4_zf_logif.h>
#include <sel4bench/sel4bench.h>
#include <time.h>

#include <math.h>

#define LEN 1000000


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

    printf("P3: hey, I'm born!\n");

		int error;
    unsigned int buffer[LEN] = {0};

    ZF_LOGF_IF(argc < 1, "Missing arguments.\n");
    seL4_CPtr ep = (seL4_CPtr) atol(argv[0]);

    ZF_LOGF_IF(argc < 1, "Missing arguments.\n");
    seL4_CPtr ep_ap = (seL4_CPtr) atol(argv[1]);

    printf("P3: Received %lu as argument 1\n", ep);
    printf("P3: Received %lu as argument 2\n", ep_ap);

    for (int i = 0; i < LEN; i++) {
      buffer[i] = i;
    }
    
    double mean = calculateMean(buffer, LEN);
    double stdDev = calculateStdDev(buffer, LEN, mean);
    printf("P3: Some random stuff = %f, %f\n", mean, stdDev);

    printf("P3: Minding my own business! \n");
    while(1);

		printf("P3: time to die! \n");
		return 0;

}

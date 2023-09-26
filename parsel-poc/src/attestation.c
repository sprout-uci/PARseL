
/*
 * Attestation process
 */

#include <stdio.h>

#include <sel4/sel4.h>
#include <sel4utils/process.h>

#include <sel4utils/sel4_zf_logif.h>
#include <sel4bench/sel4bench.h>

#include <math.h>


#define CHAL_LEN 32
#define SHA256_OUTPUT_LEN 32

#define HMAC_OUTPUT_LEN 32
#define HMAC_KEY_LEN 32

#define EDDSA_PRIVATE_KEY_LEN 32
#define EDDSA_PUBLIC_KEY_LEN 64
#define EDDSA_SIGNATURE_LEN 64

#define EXP_MAX_ITERATIONS 50


// We assume the below keys are securely stored on the device protected by hardware

static uint8_t hmac_key[HMAC_KEY_LEN] = { 
    0x10, 0x12, 0x9f, 0x46, 0x21, 0xb4, 0x79, 0xe8, 
    0x4d, 0x0d, 0x16, 0x88, 0x23, 0xf1, 0xa2, 0xd4, 
	0xdc, 0x85, 0x52, 0x5a, 0xe8, 0x79, 0xe5, 0x86, 
	0x02, 0x73, 0x91, 0x6b, 0x91, 0xc7, 0x24, 0xe9 
};

static uint8_t eddsa_key[EDDSA_PRIVATE_KEY_LEN] = { 
    0x10, 0x12, 0x9f, 0x46, 0x21, 0xb4, 0x79, 0xe8, 
    0x4d, 0x0d, 0x16, 0x88, 0x23, 0xf1, 0xa2, 0xd4, 
	0xdc, 0x85, 0x52, 0x5a, 0xe8, 0x79, 0xe5, 0x86, 
	0x02, 0x73, 0x91, 0x6b, 0x91, 0xc7, 0x24, 0xe9 
};

extern void Hacl_SHA2_256_hash(uint8_t *hash1, uint8_t *input, uint32_t len);
extern void hmac(uint8_t *mac, uint8_t *key, uint32_t keylen, uint8_t *data, uint32_t datalen);
extern void Hacl_Ed25519_sign(uint8_t *signature, uint8_t *secret, uint8_t *msg, uint32_t len1);

/* User Process (UP) related variables */
#define MAX_USER_PROCESSES 5
static uint8_t measurementMap[MAX_USER_PROCESSES][SHA256_OUTPUT_LEN];
static int user_process_counter = 0;
#define EP_UP_BADGE 0x38 // arbitrary (but unique) number for UPs' base endpoint badge



double calculateMean(int arr[], int size) {
    double sum = 0.0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum / size;
}

double calculateStdDev(int arr[], int size, double mean) {
    double sum = 0.0;
    for (int i = 0; i < size; i++) {
        double diff = arr[i] - mean;
        sum += diff * diff;
    }
    return sqrt(sum / size);
}


void populate_measurement_map(seL4_CPtr myEP) {
    
    printf("attestation: Collecting the user process measurements.\n");
    while(1){
        UNUSED seL4_MessageInfo_t tag;
        seL4_Word ps_badge = 0;

        tag = seL4_Recv(myEP, &ps_badge);

        seL4_Word msg = seL4_GetMR(0);
        printf("attestation: my badge: %lu, sender badge: %lu, message received %x\n", myEP, ps_badge, msg);
        if (msg == 0){
            seL4_SetMR(0, 0);
            seL4_Reply(tag);
            break;
        }
        else{
            ZF_LOGF_IF(seL4_MessageInfo_get_length(tag) != 8,
                "Response data from the new process was not the length expected: %d, %d.\n"
                "\tHow many registers did you set with seL4_SetMR within the new process?\n", seL4_MessageInfo_get_length(tag), sizeof(seL4_Word));

            seL4_Word measurement[8] = {
                seL4_GetMR(0),
                seL4_GetMR(1),
                seL4_GetMR(2),
                seL4_GetMR(3),
                seL4_GetMR(4),
                seL4_GetMR(5),
                seL4_GetMR(6),
                seL4_GetMR(7)
            };
            
            memcpy(measurementMap[user_process_counter], (uint8_t*) measurement, SHA256_OUTPUT_LEN);

            printf("attestation: Collected P%d measurement: %x\n", user_process_counter, measurement[0]);
            user_process_counter++;
            seL4_SetMR(0, 0);
            seL4_Reply(tag);
        }
    }
    printf("attestation: done collecting all measurements\n");
}

void sign_using_hmac(uint8_t *sig, uint8_t *key, uint32_t keylen, uint8_t *chal, uint32_t challen,
                                uint8_t *pk, uint32_t pklen, uint8_t *hash, uint32_t hashlen){

    uint8_t input_buffer[CHAL_LEN + EDDSA_PUBLIC_KEY_LEN + SHA256_OUTPUT_LEN];
    memcpy(input_buffer, chal, challen);
    memcpy(input_buffer + challen, pk, pklen);
    memcpy(input_buffer + challen + pklen, hash, hashlen);

    uint8_t digest[SHA256_OUTPUT_LEN];
    Hacl_SHA2_256_hash(digest, input_buffer, sizeof(input_buffer));

    hmac(sig, key, keylen, digest, sizeof(digest));
}

void sign_using_eddsa(uint8_t *sig, uint8_t *key, uint32_t keylen, uint8_t *chal, uint32_t challen,
                                uint8_t *pk, uint32_t pklen, uint8_t *hash, uint32_t hashlen){
    
    uint8_t input_buffer[CHAL_LEN + EDDSA_PUBLIC_KEY_LEN + SHA256_OUTPUT_LEN];
    memcpy(input_buffer, chal, challen);
    memcpy(input_buffer + challen, pk, pklen);
    memcpy(input_buffer + challen + pklen, hash, hashlen);

    uint8_t digest[SHA256_OUTPUT_LEN];
    Hacl_SHA2_256_hash(digest, input_buffer, sizeof(input_buffer));

    Hacl_Ed25519_sign(sig, key, digest, sizeof(digest));
}

void attestation_service(seL4_CPtr ep_up){
    
    int i = 0;
    unsigned long dtime[EXP_MAX_ITERATIONS] = {0}, start = 0, end = 0;
    while(1) {
        seL4_Word sender_badge = 0;
        UNUSED seL4_MessageInfo_t tag;
        printf("attestation: listening on ep cap: %x\n", ep_up);

        tag = seL4_Recv(ep_up, &sender_badge);
        int up_id = sender_badge - EP_UP_BADGE;

        ZF_LOGF_IF(up_id < 0,
            "Process sender badge is less than zero.\n"
            "\tWhich process is currently being attested?\n");

        ZF_LOGF_IF(up_id >= user_process_counter,
            "Process sender badge is greater than the max number of user processes.\n"
            "\tWhich process is currently being attested?\n");

        ZF_LOGF_IF(seL4_MessageInfo_get_length(tag) != CHAL_LEN/sizeof(seL4_Word),
            "Response data from the new process was not the length expected.\n"
            "\tHow many registers did you set with seL4_SetMR within the new process?\n");

        seL4_Word chal[CHAL_LEN/sizeof(seL4_Word)] = {
            seL4_GetMR(0),
            seL4_GetMR(1),
            seL4_GetMR(2),
            seL4_GetMR(3),
            seL4_GetMR(4),
            seL4_GetMR(5),
            seL4_GetMR(6),
            seL4_GetMR(7),
            seL4_GetMR(8)
            };

        printf("attestation: received challenge from P%d\n", up_id);

        seL4_SetMR(0, 0);
        seL4_Reply(tag);

        tag = seL4_Recv(ep_up, &sender_badge);
        up_id = sender_badge - EP_UP_BADGE;

        ZF_LOGF_IF(up_id < 0,
            "Process sender badge is less than zero.\n"
            "\tWhich process is currently being attested?\n");

        ZF_LOGF_IF(up_id >= user_process_counter,
            "Process sender badge is greater than the max number of user processes.\n"
            "\tWhich process is currently attesting?\n");

        ZF_LOGF_IF(seL4_MessageInfo_get_length(tag) != EDDSA_PUBLIC_KEY_LEN/sizeof(seL4_Word),
            "Response data from the new process was not the length expected.\n"
            "\tHow many registers did you set with seL4_SetMR within the new process?\n");

        seL4_Word pk[EDDSA_PUBLIC_KEY_LEN/sizeof(seL4_Word)] = {
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

        printf("attestation: received pk from P%d\n", up_id);

        uint8_t chal_tmp[CHAL_LEN] = {0};
        memcpy(chal_tmp, chal, CHAL_LEN);
        uint8_t pk_tmp[EDDSA_PUBLIC_KEY_LEN] = {0};
        memcpy(pk_tmp, pk, EDDSA_PUBLIC_KEY_LEN);
        uint8_t att_hash[SHA256_OUTPUT_LEN] = {0};
        memcpy(att_hash, measurementMap[up_id], SHA256_OUTPUT_LEN);
        
        uint8_t sig[EDDSA_SIGNATURE_LEN] = {0};

        // Uncomment the below code for testing HMAC
        /*
        start = sel4bench_get_cycle_count();
        sign_using_hmac(sig, hmac_key, HMAC_KEY_LEN, chal_tmp, CHAL_LEN, 
            pk_tmp, EDDSA_PUBLIC_KEY_LEN, att_hash, SHA256_OUTPUT_LEN);
        end = sel4bench_get_cycle_count();
        */

        // Uncomment the below code for testing EdDSA
        start = sel4bench_get_cycle_count();
        sign_using_eddsa(sig, eddsa_key, EDDSA_PRIVATE_KEY_LEN, chal_tmp, CHAL_LEN, 
            pk_tmp, EDDSA_PUBLIC_KEY_LEN, att_hash, SHA256_OUTPUT_LEN);
        end = sel4bench_get_cycle_count();

        dtime[i] = end - start;
        printf("attestation: TIME TAKEN to compute signature = %lu\n", dtime[i]);

        seL4_Word response[EDDSA_SIGNATURE_LEN/sizeof(seL4_Word)];
        memcpy(response, sig, EDDSA_SIGNATURE_LEN);

        printf("attestation: computed signature - %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x \n", 
            response[0], response[1], response[2], response[3],
            response[4], response[5], response[6], response[7],
            response[8], response[9], response[10], response[11],
            response[12], response[13], response[14], response[15]);
        
        seL4_SetMR(0, response[0]);
        seL4_SetMR(1, response[1]);
        seL4_SetMR(2, response[2]);
        seL4_SetMR(3, response[3]);
        seL4_SetMR(4, response[4]);
        seL4_SetMR(5, response[5]);
        seL4_SetMR(6, response[6]);
        seL4_SetMR(7, response[7]);
        seL4_SetMR(8, response[8]);
        seL4_SetMR(9, response[9]);
        seL4_SetMR(10, response[10]);
        seL4_SetMR(11, response[11]);
        seL4_SetMR(12, response[12]);
        seL4_SetMR(13, response[13]);
        seL4_SetMR(14, response[14]);
        seL4_SetMR(15, response[15]);

        seL4_Reply(tag);
        printf("attestation: replied result to P%d\n", up_id);

        i++;

        if (i == EXP_MAX_ITERATIONS) {
            // The first one is always an outlier for some reason. Just a quick fix.
            dtime[0] = dtime[EXP_MAX_ITERATIONS - 1]; 

            double mean = calculateMean(dtime, EXP_MAX_ITERATIONS);
            double stdDev = calculateStdDev(dtime, EXP_MAX_ITERATIONS, mean);

            printf("attestation: Average TIME TAKEN to sign = %f, %f\n", mean, stdDev);
            i = 0;
        }
        // break;
    }
}


int main(int argc, char **argv) {

    printf("attestation: Hi\n");

    ZF_LOGF_IF(argc < 1, "Missing arguments.\n");
    seL4_CPtr ep = (seL4_CPtr) atol(argv[0]);

    ZF_LOGF_IF(argc < 1, "Missing arguments.\n");
    seL4_CPtr ep_up = (seL4_CPtr) atol(argv[1]);

    populate_measurement_map(ep);

    attestation_service(ep_up);
    
}

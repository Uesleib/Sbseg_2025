#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../thash.h"
#include "../api.h"
#include "../fors.h"
#include "../wotsx1.h"
#include "../params.h"
#include "../randombytes.h"
#include "cycles.h"

#define SPX_MLEN 61
#define NTESTS 10000
#define SIGNATURE_LEN 17088

static void wots_gen_pkx1(unsigned char *pk, const spx_ctx* ctx,
                uint32_t addr[8]);

static int cmp_llu(const void *a, const void*b)
{
  if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

static void delta(unsigned long long *l, size_t llen)
{
    unsigned int i;
    for(i = 0; i < llen - 1; i++) {
        l[i] = l[i+1] - l[i];
    }
}


static void printfcomma (unsigned long long n)
{
    if (n < 1000) {
        printf("%llu", n);
        return;
    }
    printfcomma(n / 1000);
    printf (",%03llu", n % 1000);
}

static void printfalignedcomma (unsigned long long n, int len)
{
    unsigned long long ncopy = n;
    int i = 0;

    while (ncopy > 9) {
        len -= 1;
        ncopy /= 10;
        i += 1;  // to account for commas
    }
    i = i/3 - 1;  // to account for commas
    for (; i < len; i++) {
        printf(" ");
    }
    printfcomma(n);
}

static void display_result(double result, unsigned long long *l, size_t llen, unsigned long long mul)
{
    unsigned long long med;

    result /= NTESTS;
    delta(l, NTESTS + 1);
    med = median(l, llen);
    printf("avg. %11.2lf us (%2.2lf sec); median ", result, result / 1e6);
    printfalignedcomma(med, 12);
    printf(" cycles,  %5llux: ", mul);
    printfalignedcomma(mul*med, 12);
    printf(" cycles\n");
}

#define MEASURE_GENERIC(TEXT, MUL, FNCALL, CORR)\
    printf(TEXT);\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);\
    for(i = 0; i < NTESTS; i++) {\
        t[i] = cpucycles() / CORR;\
        FNCALL;\
    }\
    t[NTESTS] = cpucycles();\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);\
    result = ((stop.tv_sec - start.tv_sec) * 1e6 + \
        (stop.tv_nsec - start.tv_nsec) / 1e3) / (double)CORR;\
    display_result(result, t, NTESTS, MUL);
#define MEASURT(TEXT, MUL, FNCALL)\
    MEASURE_GENERIC(\
        TEXT, MUL,\
        do {\
          for (int j = 0; j < 1000; j++) {\
            FNCALL;\
          }\
        } while (0);,\
    1000);
#define MEASURE(TEXT, MUL, FNCALL) MEASURE_GENERIC(TEXT, MUL, FNCALL, 1)

int main(void)
{
    /* Make stdout buffer more responsive. */
    // setbuf(stdout, NULL);
    // init_cpucycles();

    spx_ctx ctx;

    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    uint8_t signature[SIGNATURE_LEN];
    size_t signature_len;
    unsigned char *m = malloc(SPX_MLEN);
    unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);


    unsigned long long smlen;
    unsigned long long mlen;
    
    crypto_sign_keypair(pk, sk);
    int ret;
    
    for(int i=0; i<NTESTS;i++){
        ret=crypto_sign_signature(signature, &signature_len, m, SPX_MLEN, sk);
    }
    
    clock_t time;
    double time_taken;
    
    for(int i=0; i<NTESTS;i++){
        randombytes(m, SPX_MLEN);
        
        /*
        SIGNATURE
        */
        time= clock();
        ret=crypto_sign_signature(signature, &signature_len, m, SPX_MLEN, sk);
        time=clock()-time;
    
        time_taken = ((double)time)/CLOCKS_PER_SEC; // in seconds 
        printf("%d %.0f\t\t",ret, time_taken*(1.0e+9));

        /*
        VERIFY SIGNATURE
        */
        
        time= clock();
        ret=crypto_sign_verify(signature, signature_len, m, SPX_MLEN, pk);
        time=clock()-time;
    
        time_taken = ((double)time)/CLOCKS_PER_SEC; // in seconds 
        printf("%d %.0f\n",ret, time_taken*(1.0e+9));


        // do {
        //     randombytes(&b, 1);
        //   } while(!b);
        //   sm[j % (MLEN + CRYPTO_BYTES)] += b;
        //   ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);
        //   if(!ret) {
        //     fprintf(stderr, "Trivial forgeries possible\n");
        //     return -1;
        //   }
    
    }

    // printf("Signature size: %d (%.2f KiB)\n", SPX_BYTES, SPX_BYTES / 1024.0);
    // printf("Public key size: %d (%.2f KiB)\n", SPX_PK_BYTES, SPX_PK_BYTES / 1024.0);
    // printf("Secret key size: %d (%.2f KiB)\n", SPX_SK_BYTES, SPX_SK_BYTES / 1024.0);

    free(m);
    free(sm);
    free(mout);

    return 0;
}

static void wots_gen_pkx1(unsigned char *pk, const spx_ctx *ctx,
                  uint32_t addr[8]) {
    struct leaf_info_x1 leaf;
    unsigned steps[ SPX_WOTS_LEN ] = { 0 };
    INITIALIZE_LEAF_INFO_X1(leaf, addr, steps);
    wots_gen_leafx1(pk, ctx, 0, &leaf);
}


#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../randombytes.h"
#include "../sign.h"
#include <time.h>

#define MLEN 61
#define CTXLEN 14
#define NTESTS 10000
#define SIGNATURE_LEN 4627

int main(void)
{
  size_t i, j;
  int ret;
  size_t mlen, smlen;
  uint8_t b;
  uint8_t ctx[CTXLEN] = {0};
  uint8_t m[MLEN]={""};
  uint8_t m2[MLEN + CRYPTO_BYTES];
  uint8_t sm[MLEN + CRYPTO_BYTES];
  uint8_t signature[SIGNATURE_LEN];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  clock_t time;
  double time_taken;
  snprintf((char*)ctx,CTXLEN,"test_dilitium");
  
  crypto_sign_keypair(pk, sk);
  
  // crypto_sign(sm, &smlen, m, MLEN, ctx, CTXLEN, sk);
  // printf("String: %s\n",ctx);
  // printf("M: %s\nMSize: %lu\n",m,sizeof(m));
  // printf("SM %s\n SM_size: %lu \n",sm,sizeof(sm));


  for(i=0; i<NTESTS; i++){
    randombytes(m, MLEN);
    crypto_sign_signature(signature, &smlen, m, MLEN, ctx, CTXLEN, sk);
  }


  for(i = 0; i < NTESTS; ++i) {
    randombytes(m, MLEN);
    
    /*
    Signing
    */
    time= clock();
    ret=crypto_sign_signature(signature, &smlen, m, MLEN, ctx, CTXLEN, sk);
    time=clock()-time;

    time_taken = ((double)time)/CLOCKS_PER_SEC ; // in nanoseconds 
    printf("%d %f\t\t",ret, time_taken*(1.0e+9));
  

    /*
    verification
    */
    time=clock();
    ret= crypto_sign_verify(signature,smlen,m,MLEN,ctx,CTXLEN,pk);
    time=clock()-time;

    time_taken = ((double)time)/CLOCKS_PER_SEC; // in nanoseconds     
    printf("%d\t%f\n",ret, time_taken*1.0e+9);

    
    // if(ret) {
    //   fprintf(stderr, "Verification failed\n");
    //   return -1;
    // }
    // if(smlen != MLEN + CRYPTO_BYTES) {
    //   fprintf(stderr, "Signed message lengths wrong\n");
    //   return -1;
    // }
    // if(mlen != MLEN) {
    //   fprintf(stderr, "Message lengths wrong\n");
    //   return -1;
    // }
    // for(j = 0; j < MLEN; ++j) {
    //   if(m2[j] != m[j]) {
    //     fprintf(stderr, "Messages don't match\n");
    //     return -1;
    //   }
    // }

    // randombytes((uint8_t *)&j, sizeof(j));
    // do {
    //   randombytes(&b, 1);
    // } while(!b);
    // sm[j % (MLEN + CRYPTO_BYTES)] += b;
    // ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);
    // if(!ret) {
    //   fprintf(stderr, "Trivial forgeries possible\n");
    //   return -1;
    // }
  }

  // printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
  // printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
  // printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);

  return 0;
}

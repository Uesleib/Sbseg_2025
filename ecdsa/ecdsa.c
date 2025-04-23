#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#define NTESTS 10000
#define MESSAGE_SIZE 61

void handleErrors(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static int fd = -1;
void randombytes(unsigned char *x, unsigned long long xlen)
{
    unsigned long long i;

    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom", O_RDONLY);
            if (fd != -1) {
                break;
            }
            sleep(1);
        }
    }

    while (xlen > 0) {
        if (xlen < 1048576) {
            i = xlen;
        }
        else {
            i = 1048576;
        }

        i = (unsigned long long)read(fd, x, i);
        if (i < 1) {
            sleep(1);
            continue;
        }

        x += i;
        xlen -= i;
    }
}

int main(int argc, char **argv) {

    int input=atoi(argv[1]);
    EVP_PKEY *pkey = NULL;

    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    size_t sig_len;
    unsigned char *signature = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char message[MESSAGE_SIZE] = {""};
    
    // Generate ECDSA key using secp256k1
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_keygen_init(pctx);
    
    OpenSSL_add_all_algorithms();
    if(input==0){
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1);
    }
    else{
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1);
    }
    
    printf("%s %d\n",argv[1],EVP_PKEY_generate(pctx, &pkey));
    EVP_PKEY *private_key = EVP_PKEY_dup(pkey);
    EVP_PKEY *public_key = EVP_PKEY_dup(pkey);
    if (!private_key || !public_key) handleErrors("key erros");
    
    
    
    time_t time;
    int ret;
    double time_taken;

    for(int i=0; i<NTESTS;i++){          
            randombytes(message,MESSAGE_SIZE);
            
            //
            //Signature
            //
            if(!(mdctx = EVP_MD_CTX_new())) handleErrors("falha");       
            if(1 != EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey))handleErrors("falha");
            if(1 != EVP_DigestSignUpdate(mdctx, message, strlen(message))) handleErrors("falha");
            
            if(1 != EVP_DigestSignFinal(mdctx, NULL, &sig_len)) handleErrors("falha");
        
            if(!(signature = OPENSSL_malloc(sizeof(unsigned char) * (sig_len)))) handleErrors("falha");

            if(1 != (ret=EVP_DigestSignFinal(mdctx, signature, &sig_len))) handleErrors("falha");
            printf("%d ",ret);
        
        
        
            //
            //Verify
            //
            if(1 != EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, pkey)) handleErrors("falha");
            
            if(1 != EVP_DigestVerifyUpdate(mdctx, message, strlen(message))) handleErrors("falha");
            
            if(1 != (ret=EVP_DigestVerifyFinal(mdctx, signature, sig_len))) handleErrors("falha final verifica");
                

                printf("%d,",ret);
            
                OPENSSL_free(signature);
            EVP_MD_CTX_free(mdctx);
            
            
    }

    printf("\n");

    if(input==0){
        for(int i=0; i<NTESTS;i++){
            randombytes(message,MESSAGE_SIZE);
                
            //
            //Signature
            //
            if(!(mdctx = EVP_MD_CTX_new())) handleErrors("falha");       
            if(1 != EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey))handleErrors("falha");
            if(1 != EVP_DigestSignUpdate(mdctx, message, strlen(message))) handleErrors("falha");
                
            if(1 != EVP_DigestSignFinal(mdctx, NULL, &sig_len)) handleErrors("falha");
            
            if(!(signature = OPENSSL_malloc(sizeof(unsigned char) * (sig_len)))) handleErrors("falha");
            
            time=clock();
            ret= EVP_DigestSignFinal(mdctx, signature, &sig_len);
            time=clock()-time;

            time_taken = ((double)time)/CLOCKS_PER_SEC ; 
            printf("%d\t%.0f\t\t",ret, time_taken*(1.0e+9));
            
            
            
            //
            //Verify
            //
            if(1 != EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, pkey)) handleErrors("falha");
            
            if(1 != EVP_DigestVerifyUpdate(mdctx, message, strlen(message))) handleErrors("falha");
            
            // time=clock();
            ret=EVP_DigestVerifyFinal(mdctx, signature, sig_len);
            time=clock()-time;
           
            time_taken = ((double)time)/CLOCKS_PER_SEC ; 
            printf("%d\t%.0f\n",ret, time_taken*(1.0e+9));
            
            
            OPENSSL_free(signature);
            EVP_MD_CTX_free(mdctx);
            
        }
    }else{

        for(int i=0; i<NTESTS;i++){
            randombytes(message,MESSAGE_SIZE);
                
            //
            //Signature
            //
            if(!(mdctx = EVP_MD_CTX_new())) handleErrors("falha");       
            if(1 != EVP_DigestSignInit(mdctx, &pctx, EVP_sha384(), NULL, private_key))handleErrors("falha");
            if(1 != EVP_DigestSignUpdate(mdctx, message, strlen(message))) handleErrors("falha");
                
            if(1 != EVP_DigestSignFinal(mdctx, NULL, &sig_len)) handleErrors("falha");
            
            if(!(signature = OPENSSL_malloc(sizeof(unsigned char) * (sig_len)))) handleErrors("falha");
            
            time=clock();
            ret= EVP_DigestSignFinal(mdctx, signature, &sig_len);
            time=clock()-time;

            time_taken = ((double)time)/CLOCKS_PER_SEC ; 
            printf("%d\t%.0f\t\t",ret, time_taken*(1.0e+9));
            
            
            
            //
            //Verify
            //
            if(1 != EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha384(), NULL, public_key)) handleErrors("falha");
            
            if(1 != EVP_DigestVerifyUpdate(mdctx, message, strlen(message))) handleErrors("falha");
            
            time=clock();
            ret=EVP_DigestVerifyFinal(mdctx, signature, sig_len);
            time=clock()-time;
            
            time_taken = ((double)time)/CLOCKS_PER_SEC ; 
            printf("%d\t%.0f\n",ret, time_taken*(1.0e+9));

            OPENSSL_free(signature);
            EVP_MD_CTX_free(mdctx);
            
        }
    }

 

    // Cleanup
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);

    return 0;
}

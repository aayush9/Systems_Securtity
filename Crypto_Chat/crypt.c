#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <errno.h>
#include <openssl/err.h>

#define KDC_PORT 4246
#define MAIN_PORT 42426


char **tokenize(char _s[]){
	char *rest = NULL, *token;
	int len = 0;
	char *s = malloc(1024);
	strcpy(s,_s);
	char **arr = malloc(sizeof(char *) * 42);
	for(token=strtok_r(s," ",&rest);token;token=strtok_r(NULL," ",&rest)){
        arr[len] = malloc(205);
        strcpy(arr[len],token);
        ++len;
    }
    return arr;
}


// Reference: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int enc(unsigned char *in, unsigned char *key, int encrypt){
	int in_len = 0;
	for(int i=0;i<1024;++i) if(in[i]) in_len = i+1;
	unsigned char iv[16];
	for(int i=0;i<16;++i) iv[i] = 0;
	unsigned char *out =  malloc(1024);
	memset(out,0,1024);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	int len=0;
	int plaintext_len;
	if(encrypt == 1){
		EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
		EVP_EncryptUpdate(ctx, out, &len, in, in_len);
		plaintext_len = len;
		EVP_EncryptFinal_ex(ctx, out + len, &len);
		plaintext_len += len;
		out[plaintext_len] = 0;
	} else {
		EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc(), NULL, key, iv);
		EVP_DecryptUpdate(ctx,out,&len,in,in_len);
		plaintext_len = len;
		EVP_DecryptFinal_ex(ctx,out+len,&len);
		plaintext_len += len;
		out[plaintext_len] = 0;
	}
	EVP_CIPHER_CTX_free(ctx);
	memset(in,0,1024);
	for(int i=0;i<plaintext_len;++i) in[i]=out[i];
	return plaintext_len;
}

int enc_asymmetric(unsigned char *in, unsigned char *key, int encrypt){
	unsigned char *out = malloc(1024);
	int in_len = 0;
	for(int i=0;i<1024;++i) if(in[i]) in_len = i+1;


	if(encrypt){
		BIO *keybio = BIO_new_mem_buf((void*)key, -1);
		RSA *rsa;
		rsa = PEM_read_bio_RSAPublicKey(keybio, 0,0, 0);
		RSA_public_encrypt(strlen(in),in,out, rsa, RSA_PKCS1_OAEP_PADDING);
		RSA_free(rsa);
		BIO_free_all(keybio);
	} else {
		BIO *keybio = BIO_new_mem_buf((void*)key, -1);
		RSA *rsa;
		rsa = PEM_read_bio_RSAPrivateKey(keybio, 0,0, 0);
		RSA_private_decrypt(in_len, (unsigned char*)in, (unsigned char*)out, rsa, RSA_PKCS1_OAEP_PADDING);
		
		RSA_free(rsa);
	  	BIO_free_all(keybio);
	}
	for(int i=0;i<1024;++i) in[i] = out[i];
	return 0;
}

int sign(unsigned char *in, unsigned char *key, int sign){
	unsigned char *out = malloc(1024);
	int in_len = 0;
	for(int i=0;i<1024;++i) if(in[i]) in_len = i+1;


	if(sign){
		BIO *keybio = BIO_new_mem_buf((void*)key, -1);
		RSA *rsa;
		rsa = PEM_read_bio_RSAPrivateKey(keybio, 0,0, 0);
		RSA_private_encrypt(strlen(in),in,out, rsa, RSA_PKCS1_PADDING);
		RSA_free(rsa);
		BIO_free_all(keybio);
	} else {
		BIO *keybio = BIO_new_mem_buf((void*)key, -1);
		RSA *rsa;
		rsa = PEM_read_bio_RSAPublicKey(keybio, 0,0, 0);
		RSA_public_decrypt(in_len, in, out, rsa, RSA_PKCS1_PADDING);
		RSA_free(rsa);
	  	BIO_free_all(keybio);
	}

	for(int i=0;i<1024;++i) in[i] = out[i];
	return 0;
}

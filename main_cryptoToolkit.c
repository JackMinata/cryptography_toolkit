#include <openssl/aes.h>  // this version uses openssl. Need to code it independently.
#include <openssl/rand.h>
#include <string.h>

void generateKey(unsigned char *key) {
    // Securely generate a random key for AES 256
    RAND_bytes(key, 32); 
}

void aesEncrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext) {
    // AES encryption logic using OpenSSL

    // Initialize the encryption key structure
    AES_KEY enc_key;
    AES_set_encrypt_key(key, 256, &enc_key);

    // Encrypt the plaintext
    // Note: The plaintext length must be a multiple of AES_BLOCK_SIZE
    AES_encrypt(plaintext, ciphertext, &enc_key);
}

void aesDecrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext) {
    // AES decryption logic using OpenSSL

    // Initialize the decryption key structure
    AES_KEY dec_key;
    AES_set_decrypt_key(key, 256, &dec_key);

    // Decrypt the ciphertext
    AES_decrypt(ciphertext, plaintext, &dec_key);
}

int main() {
    unsigned char key[32]; // 256 bits AES key
    unsigned char plaintext[128]; // Placeholder for plaintext
    unsigned char ciphertext[128]; // Placeholder for ciphertext

    // Generate or set a fixed key
    generateKey(key);

    printf("Enter plaintext to crypto: ");
    fgets((char *)plaintext, 128, stdin); // Simple input, not production-safe

    // Encrypt
    aesEncrypt(plaintext, key, ciphertext);
    printf("Encrypted text: ");
    // Print ciphertext in a readable format

    // Decrypt
    aesDecrypt(ciphertext, key, plaintext);
    printf("Decrypted text: %s\n", plaintext);

    return 0;
}

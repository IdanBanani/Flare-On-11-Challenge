
 #include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Define the function pointer type for RSA_public_decrypt
typedef int (*RSA_public_decrypt_t)(unsigned int flen, unsigned char *from, unsigned char *to, void *rsa, unsigned int padding);

// Function to get the base address of liblzma.so.5 from /proc/self/maps
uintptr_t get_liblzma_base() {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        perror("fopen");
        return 0;
    }

    char line[256];
    uintptr_t base_addr = 0;

    // Read each line of the memory mappings
    while (fgets(line, sizeof(line), maps)) {
        // Check if the line contains "liblzma.so.5"
        if (strstr(line, "liblzma.so.5")) {
            sscanf(line, "%lx", &base_addr);
            break;  // Stop after finding the library
        }
    }

    fclose(maps);
    return base_addr;
}


int main() {
        unsigned char from[] = {
  0x48, 0x7a, 0x40, 0xc5, 0x94, 0x3d, 0xf6, 0x38, 0xa8, 0x18, 0x13, 0xe2,
  0xde, 0x63, 0x18, 0xa5, 0x07, 0xf9, 0xa0, 0xba, 0x2d, 0xbb, 0x8a, 0x7b,
  0xa6, 0x36, 0x66, 0xd0, 0x8d, 0x11, 0xa6, 0x5e, 0xc9, 0x14, 0xd6, 0x6f,
  0xf2, 0x36, 0x83, 0x9f, 0x4d, 0xcd, 0x71, 0x1a, 0x52, 0x86, 0x29, 0x55,
  0x58, 0x58, 0xd1, 0xb7, 0xf9, 0xa7, 0xc2, 0x0d, 0x36, 0xde, 0x0e, 0x19,
  0xea, 0xa3, 0x05, 0x96, 0xda, 0x59, 0xb9, 0xb9, 0x0d, 0x17, 0x8f, 0x41,
  0x42, 0x3d, 0x7e, 0xeb, 0x15, 0x07, 0xb5, 0xdc, 0x03, 0x9c, 0xb8, 0x49,
  0xa8, 0x59, 0x98, 0xcc, 0x61, 0x1f, 0x37, 0x9b, 0x4d, 0x0a, 0xf2, 0x50,
  0xbd, 0xab, 0x37, 0x2d
};

    // Get the base address of liblzma.so.5
    uintptr_t base_address = get_liblzma_base();
    if (base_address == 0) {
        fprintf(stderr, "Failed to find base address of liblzma.so.5\n");
        return EXIT_FAILURE;
    }

    // Calculate the address of RSA_public_decrypt using its known offset (0x9820)
    uintptr_t rsa_dec_addr = base_address + 0x9820;

    // Cast the address to the correct function pointer type
    RSA_public_decrypt_t rsa_dec = (RSA_public_decrypt_t)rsa_dec_addr;

    // Prepare the arguments for the RSA_public_decrypt function
    unsigned int flen = 200/* length of the input data, e.g., sizeof(from_array) */;
   
    unsigned char to[256] = {0};  // Output buffer (size depends on your RSA key size)
    void *rsa = NULL/* Pointer to your RSA structure */;
    unsigned int padding = 1/* Padding type (e.g., RSA_PKCS1_PADDING) */;

    // Call the RSA_public_decrypt function
    int ret = rsa_dec(flen, from, to, rsa, padding);
    
    if (ret >= 0) {
        printf("RSA_public_decrypt succeeded, output size: %d\n", ret);
    } else {
        printf("RSA_public_decrypt failed with error code: %d\n", ret);
    }

    return 0;
}

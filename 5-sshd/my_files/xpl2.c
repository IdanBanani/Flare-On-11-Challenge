#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
void execute_payload(const char *filename) {
    // Open the payload file
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Get the size of the file
    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        perror("fstat");
        close(fd);
        exit(EXIT_FAILURE);
    }
    
    size_t filesize = sb.st_size;

    // Memory map the file
    void *mapped = mmap(NULL, filesize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Close the file descriptor as it's no longer needed
    close(fd);

    // Cast the mapped memory to a function pointer
    void (*func)() = mapped;

    // Execute the payload
    func();

    // Unmap the memory (optional)
    munmap(mapped, filesize);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <payload_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    execute_payload(argv[1]);

    return EXIT_SUCCESS;
}
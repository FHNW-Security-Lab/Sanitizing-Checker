#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

void test_stack_protection(void);
void test_nx(void);
void test_aslr_pie(void);
void test_relro(void);
void test_asan(void);
void test_ubsan(void);
int main(int, char**);

// Function to test stack buffer overflow
void test_stack_protection(void) {
    char buffer[10];
    printf("\nTesting Stack Protection:\n");
    printf("Attempting to write beyond buffer bounds...\n");
    // Intentionally commented out to prevent warning
    // memset(buffer, 'A', 20); // buffer overflow
    // Instead, demonstrate with a loop
    for(int i = 0; i < 20; i++) {
        buffer[i] = 'A';  // Will overflow after i > 9
    }
}

// Function to test executable stack
void test_nx(void) {
    printf("\nTesting NX/DEP:\n");
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("NX/DEP is likely enabled (couldn't allocate executable memory)\n");
    } else {
        printf("Warning: Could allocate executable memory\n");
        munmap(page, 4096);
    }
}

// Function to test ASLR/PIE
void test_aslr_pie(void) {
    printf("\nTesting ASLR/PIE:\n");
    printf("Stack address: %p\n", (void*)&test_aslr_pie);
    void* heap_ptr = malloc(1);
    printf("Heap address: %p\n", heap_ptr);
    if (heap_ptr) free(heap_ptr);
    printf("Program address: %p\n", (void*)&test_aslr_pie);
}

// Function to test RELRO
void test_relro(void) {
    printf("\nTesting RELRO:\n");
    printf("Note: RELRO status should be checked using 'readelf -l binary | grep RELRO'\n");
}

// Function to test Address Sanitizer
void test_asan(void) {
    printf("\nTesting Address Sanitizer:\n");
    char *ptr = (char*)malloc(10);
    if (ptr) {
        ptr[10] = 'A'; // Out of bounds write
        free(ptr);
    }
}

// Function to test undefined behavior
void test_ubsan(void) {
    printf("\nTesting Undefined Behavior Sanitizer:\n");
    int zero = 0;
    int result = 42 / zero; // Division by zero
    printf("Result: %d\n", result);
}

int main(int argc, char *argv[]) {
    (void)argc;  // Suppress unused parameter warning
    printf("Security Features Test Program\n");
    printf("==============================\n");
    printf("Binary: %s\n\n", argv[0]);

    // Test various security features
    test_aslr_pie();
    test_nx();
    test_relro();
    
    printf("\nWarning: The following tests may crash the program\n");
    printf("Run each test separately by uncommenting them in the code\n");
    
    // Uncomment to test specific features:
    //test_stack_protection();
    //test_asan();
    //test_ubsan();

    return 0;
}


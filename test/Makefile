# Makefile
CC = clang
CFLAGS_COMMON = -Wall -Wextra

# Base security flags
PIE_FLAG = -fpie -fPIE
RELRO_FLAG = -Wl,-z,relro,-z,now
STACK_PROT_FLAG = -fstack-protector-strong
NX_FLAG = -Wl,-z,noexecstack
FORTIFY_FLAG = -D_FORTIFY_SOURCE=2 -O2

# All security flags combined
ALL_SECURITY = $(PIE_FLAG) $(RELRO_FLAG) $(STACK_PROT_FLAG) $(NX_FLAG) $(FORTIFY_FLAG)

# Sanitizer flags
ASAN_FLAG = -fsanitize=address
TSAN_FLAG = -fsanitize=thread
MSAN_FLAG = -fsanitize=memory
UBSAN_FLAG = -fsanitize=undefined

# Updated trace flags
TRACE_EDGE_FLAG = -fsanitize-coverage=edge,trace-pc-guard
TRACE_BB_NO_GUARD_FLAG = -fsanitize-coverage=trace-pc
TRACE_BB_FLAG = -fsanitize-coverage=bb,trace-pc-guard
TRACE_FUNC_FLAG = -fsanitize-coverage=func,trace-pc-guard

all: test1 test2 test3 test4 test5 test6 test7 test8 test9 test10 test11 test12 test13

# 1) All security on
test1: security_test.c
	$(CC) $(CFLAGS_COMMON) $(ALL_SECURITY) $< -o security_all_on

# 2) All security off
test2: security_test.c
	$(CC) $(CFLAGS_COMMON) -fno-pie -Wl,-no-pie -Wl,-z,norelro -fno-stack-protector -Wl,-z,execstack $< -o security_all_off

# 3) Only PIE on
test3: security_test.c
	$(CC) $(CFLAGS_COMMON) $(PIE_FLAG) $< -o security_only_pie

# 4) Only RELRO on
test4: security_test.c
	$(CC) $(CFLAGS_COMMON) -fno-pie -Wl,-no-pie $(RELRO_FLAG) -fno-stack-protector -Wl,-z,execstack $< -o security_only_relro

# 5) Only stack protection on
test5: security_test.c
	$(CC) $(CFLAGS_COMMON) -fno-pie -Wl,-no-pie -Wl,-z,norelro $(STACK_PROT_FLAG) -Wl,-z,execstack $< -o security_only_stack

# 6) All security + Address Sanitizer
test6: security_test.c
	$(CC) $(CFLAGS_COMMON) $(ALL_SECURITY) $(ASAN_FLAG) $< -o security_san_address

# 7) All security + Thread Sanitizer
test7: security_test.c
	$(CC) $(CFLAGS_COMMON) $(ALL_SECURITY) $(TSAN_FLAG) $< -o security_san_thread

# 8) All security + Memory Sanitizer
test8: security_test.c
	$(CC) $(CFLAGS_COMMON) $(ALL_SECURITY) $(MSAN_FLAG) $< -o security_san_memory

# 9) All security + Undefined Behavior Sanitizer
test9: security_test.c
	$(CC) $(CFLAGS_COMMON) $(ALL_SECURITY) $(UBSAN_FLAG) $< -o security_san_undefined

# 10) All security + Edge trace
test10: security_test.c
	$(CC) $(CFLAGS_COMMON) $(ALL_SECURITY) $(TRACE_EDGE_FLAG) $< -o security_trace_edge

# 11) All security + Basic Block trace without guard
test11: security_test.c trace_pc_support.c
	$(CC) $(CFLAGS_COMMON) $(ALL_SECURITY) $(TRACE_BB_NO_GUARD_FLAG) $^ -o security_trace_bb_no_guard

# 12) All security + Basic Block trace
test12: security_test.c
	$(CC) $(CFLAGS_COMMON) $(ALL_SECURITY) $(TRACE_BB_FLAG) $< -o security_trace_bb

# 13) All security + Function trace
test13: security_test.c
	$(CC) $(CFLAGS_COMMON) $(ALL_SECURITY) $(TRACE_FUNC_FLAG) $< -o security_trace_func

clean:
	rm -f security_all_on \
		security_all_off \
		security_only_pie \
		security_only_relro \
		security_only_stack \
		security_san_address \
		security_san_thread \
		security_san_memory \
		security_san_undefined \
		security_trace_edge \
		security_trace_bb_no_guard \
		security_trace_bb \
		security_trace_func

.PHONY: all test1 test2 test3 test4 test5 test6 test7 test8 test9 test10 test11 test12 test13 clean


# TARGETS := small_matmul medium_matmul big_matmul huge_matmul insane_matmul
TARGETS := small_matmul medium_matmul big_matmul huge_matmul

# example use case: 
# - PREFIX="../../llvm-project/build/bin" make all
ifndef PREFIX
$(error You must specify PREFIX=<path>, which is the path to your llvm-project bin/)
endif

all: $(TARGETS)

$(TARGETS):
	python3 create_bpf_program.py $@
	$(PREFIX)/clang -emit-llvm -S rolled_$@.bpf.c -O0 -target bpf -mcpu=duotronic -fno-unroll-loops
	$(PREFIX)/llc -march=bpf -mcpu=duotronic -filetype=obj -o rolled_$@.bpf.o -O0 -bpf-stack-size=40000 rolled_$@.bpf.ll
	$(PREFIX)/llvm-objcopy -O binary --only-section=.text rolled_$@.bpf.o ../test/rolled_$@.o

	$(PREFIX)/clang -emit-llvm -S unrolled_$@.bpf.c -O0 -target bpf -mcpu=duotronic -fno-unroll-loops
	$(PREFIX)/llc -march=bpf -mcpu=duotronic -filetype=obj -o unrolled_$@.bpf.o -O0 -bpf-stack-size=1000000 unrolled_$@.bpf.ll
	$(PREFIX)/llvm-objcopy -O binary --only-section=.text unrolled_$@.bpf.o ../test/unrolled_$@.o

.PHONY: all $(TARGETS)


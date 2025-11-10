TARGETS := small_mod medium_mod big_mod huge_mod insane_mod

# example use case: 
# - PREFIX="../../llvm-project/build/bin" make all
ifndef PREFIX
$(error You must specify PREFIX=<path>, which is the path to your llvm-project bin/)
endif

all: $(TARGETS)

$(TARGETS):
	python3 create_bpf_program.py $@
	$(PREFIX)/clang -emit-llvm -S $@.bpf.c -O0 -target bpf -mcpu=duotronic -fno-unroll-loops
	$(PREFIX)/llc -march=bpf -mcpu=duotronic -filetype=obj -o $@.bpf.o -O0 -bpf-stack-size=20000 $@.bpf.ll
	$(PREFIX)/llvm-objcopy -O binary --only-section=.text $@.bpf.o ../test/$@.o

.PHONY: all $(TARGETS)


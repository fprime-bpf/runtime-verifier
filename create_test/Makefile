# TARGETS := small_matmul medium_matmul big_matmul huge_matmul insane_matmul
TARGETS := small_matmul medium_matmul big_matmul huge_matmul
CACHES := cache_optimal cache_unoptimal

# example use case: 
# - PREFIX="../../llvm-project/build/bin" make all
ifndef PREFIX
$(error You must specify PREFIX=<path>, which is the path to your llvm-project bin/)
endif

all: $(TARGETS)

define build_one
	python3 create_$(1)_bpf_program.py $(2)
	$(PREFIX)/clang -emit-llvm -S rolled_$(2)_$(1).bpf.c -O0 -target bpf -mcpu=duotronic -fno-unroll-loops
	$(PREFIX)/llc -march=bpf -mcpu=duotronic -filetype=obj -o rolled_$(2)_$(1).bpf.o -O0 -bpf-stack-size=40000 rolled_$(2)_$(1).bpf.ll
	$(PREFIX)/llvm-objcopy -O binary --only-section=.text rolled_$(2)_$(1).bpf.o ../test/rolled_$(2)_$(1).o

	$(PREFIX)/clang -emit-llvm -S unrolled_$(2)_$(1).bpf.c -O0 -target bpf -mcpu=duotronic -fno-unroll-loops
	$(PREFIX)/llc -march=bpf -mcpu=duotronic -filetype=obj -o unrolled_$(2)_$(1).bpf.o -O0 -bpf-stack-size=1000000 unrolled_$(2)_$(1).bpf.ll
	$(PREFIX)/llvm-objcopy -O binary --only-section=.text unrolled_$(2)_$(1).bpf.o ../test/unrolled_$(2)_$(1).o
endef

$(TARGETS):
	$(foreach C,$(CACHES),$(call build_one,$(C),$@))

.PHONY: all $(TARGETS)


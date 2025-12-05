#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 PREFIX "
    echo "Example: $0 ../../llvm-project/build/bin"
    exit 1
fi

PREFIX=$1

TARGETS=(20 44 64 88)
CACHES=(opt unopt)

for target in "${TARGETS[@]}"; do
  for cache in "${CACHES[@]}"; do
    python3 "create_${cache}_bpf_program.py" "${target}"

	filehandle="rolled_${target}x${target}_${cache}"
    "${PREFIX}/clang" -emit-llvm -S "${filehandle}.bpf.c" -O0 -target bpf -mcpu=duotronic -fno-unroll-loops
    "${PREFIX}/llc" -march=bpf -mcpu=duotronic -filetype=obj -o "${filehandle}.bpf.o" -O0 -bpf-stack-size=4000000 "${filehandle}.bpf.ll"
    "${PREFIX}/llvm-objcopy" -O binary --only-section=.text "${filehandle}.bpf.o" "../test/${filehandle}.o"

	echo "created $filehandle under test/"


	filehandle="unrolled_${target}x${target}_${cache}"
    "${PREFIX}/clang" -emit-llvm -S "${filehandle}.bpf.c" -O0 -target bpf -mcpu=duotronic -fno-unroll-loops
    "${PREFIX}/llc" -march=bpf -mcpu=duotronic -filetype=obj -o "${filehandle}.bpf.o" -O0 -bpf-stack-size=10000000 "${filehandle}.bpf.ll"
    "${PREFIX}/llvm-objcopy" -O binary --only-section=.text "${filehandle}.bpf.o" "../test/${filehandle}.o"

	echo "created $filehandle under test/"
  done
done


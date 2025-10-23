# bpf-runtime-verifier

## Prerequisites

```sh
# uv
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Usage

Run the program with an ebpf program with a few restrictions: 

Program must produce a directed, acyclic graph. This means no, or unrolled loops.
Don't supply an elf object, just the ebpf instructions.
See section below for how to do this.

```sh
uv run main.py ebpf_object.o
```

### get instructions only from elf format

```sh
llvm-objcopy -O binary --only-section=.text program.bpf.o a.o
```


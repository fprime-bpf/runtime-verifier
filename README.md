# bpf-runtime-verifier

## Prerequisites

```sh
# uv
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Usage

Run the program with an ebpf object file.
Don't supply an elf object, just the ebpf instructions.

```sh
uv run main.py ebpf_object.o
```

import random
import sys

def get_begin(arr_size: int):
    return f"""
#include "bpf_shim.h"
#define ARR_SIZE {arr_size}
int main() {{
    void *mat_map_1 = MAP_BY_FD(0), *result;
    int mat[ARR_SIZE], mod = 0, i = 0;

"""

def get_end():
    return """
    return 0;
}
"""


def get_middle(arr_size: int):
    middle = ''
            
    for i in range(arr_size):
        middle += f"    i = {i};\n";
        middle += f"    mat[{i}] = *(int *)bpf_map_lookup_elem(mat_map_1, &i);\n";

    return middle



def main():
    assert len(sys.argv) == 2
    name = sys.argv[1]
    filename = f"{name}.bpf.c"
    arr_size = 0
    match name:
        case "small_mod":
            arr_size = 8
        case "medium_mod":
            arr_size = 32
        case "big_mod":
            arr_size = 128
        case  "huge_mod":
            arr_size = 512
        case "insane_mod":
            arr_size = 2048
        case _:
            raise Exception(f"bad argument")
    begin = get_begin(arr_size)
    middle = get_middle(arr_size)
    end = get_end()
    # like every story
    contents = begin + middle + end
    with open(filename, "w") as f:
        f.write(contents)


if __name__ == "__main__":
    main()

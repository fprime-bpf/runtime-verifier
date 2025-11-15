import sys

def get_begin(arr_size: int, rolled: bool):
    begin = f"""
#include "bpf_shim.h"
#define MAT_DIM {arr_size}
#define MAT_SIZE (MAT_DIM * MAT_DIM)
int main() {{
    void *mat_map_1 = MAP_BY_FD(0), *mat_map_2 = MAP_BY_FD(1), *mat_map_res = MAP_BY_FD(2), *result;
    int mat_1[MAT_SIZE], mat_2[MAT_SIZE], mat_res[MAT_SIZE];
    int i, j, k;


"""


    if rolled:
        begin += """
    // Read in 2 matrices
    for (i = 0; i < MAT_SIZE; i++) {
        result = bpf_map_lookup_elem(mat_map_1, &i);
        mat_1[i] = *(int *)result;

        result = bpf_map_lookup_elem(mat_map_2, &i);
        mat_2[i] = *(int *)result;
    }
"""
    else:
        for i in range(arr_size * arr_size):
            begin += f"    i = {i};\n"
            begin += f"    result = bpf_map_lookup_elem(mat_map_1, &i);\n"
            begin += f"    mat_1[i] = *(int *)result;\n"
            begin += f"    result = bpf_map_lookup_elem(mat_map_2, &i);\n"
            begin += f"    mat_2[i] = *(int *)result;\n"

    return begin

def get_end(arr_size: int, rolled: bool):
    end = ""

    if rolled:
        end += """
    // Write back to map
    for (i = 0; i < MAT_SIZE; i++) {
        bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    }
"""

    else:
        for i in range(arr_size):
            end += f"    i = {i};\n" 
            end += f"    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);\n"

    end += "    return 0;\n"
    end += "}\n"

    return end


def get_middle(arr_size: int, rolled: bool):
    middle = ''
            
    if rolled:
        middle += """
    // Do multiplication
    for (i = 0; i < MAT_DIM; i++) {
        for (j = 0; j < MAT_DIM; j++) {
            mat_res[i * MAT_DIM + j] = 0;
            for (k = 0; k < MAT_DIM; k++) {
                mat_res[i * MAT_DIM + j] += mat_1[i * MAT_DIM + k] * mat_2[k * MAT_DIM + j];
            }
        }
    }
"""

    else: 
        for i in range(arr_size):
            for j in range(arr_size):
                middle += f"\n    i = {i}, j = {j};\n";
                middle += f"    mat_res[i * MAT_DIM + j] = 0;\n";
                for k in range(arr_size):
                    middle += f"    k = {k};\n";
                    middle += f"    mat_res[i * MAT_DIM + j] += mat_1[i * MAT_DIM + k] * mat_2[k * MAT_DIM + j];\n";

    return middle



def main():
    assert len(sys.argv) == 2
    name = sys.argv[1]
    filename = f"{name}.bpf.c"
    arr_size = 0
    match name:
        case "small_matmul":
            arr_size = 4
        case "medium_matmul":
            arr_size = 10
        case "big_matmul":
            arr_size = 16
        case  "huge_matmul":
            arr_size = 32
        # case "insane_matmul":
        #     arr_size = 2048
        case _:
            raise Exception(f"bad argument")


    # unrolled 
    begin = get_begin(arr_size, rolled=False)
    middle = get_middle(arr_size, rolled=False)
    end = get_end(arr_size, rolled=False)
    contents = begin + middle + end
    with open(f"unrolled_{filename}", "w") as f:
        f.write(contents)


    # rolled
    begin = get_begin(arr_size, rolled=True)
    middle = get_middle(arr_size, rolled=True)
    end = get_end(arr_size, rolled=True)
    contents = begin + middle + end
    with open(f"rolled_{filename}", "w") as f:
        f.write(contents)


if __name__ == "__main__":
    main()

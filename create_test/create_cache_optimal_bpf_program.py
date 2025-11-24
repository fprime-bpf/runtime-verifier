import sys


# ib can be any even positive integer
IB_SIZE = 4
# kb can be any positive integer
KB_SIZE = 4
# both must be divisors of mat dim


def get_begin(mat_dim: int, rolled: bool):
    begin = f"""
#include "bpf_shim.h"
#define MAT_DIM {mat_dim}
#define MAT_SIZE (MAT_DIM * MAT_DIM)
#define IB {IB_SIZE}
#define KB {KB_SIZE}
int main() {{
    void *mat_map_1 = MAP_BY_FD(0), *mat_map_2 = MAP_BY_FD(1), *mat_map_res = MAP_BY_FD(2), *result;
    int mat_1[MAT_SIZE], mat_2[MAT_SIZE], mat_res[MAT_SIZE];
    int i, j, k, ii, kk;
    int acc00, acc01, acc10, acc11;

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
        for i in range(mat_dim * mat_dim):
            begin += f"    i = {i};\n"
            begin += f"    result = bpf_map_lookup_elem(mat_map_1, &i);\n"
            begin += f"    mat_1[i] = *(int *)result;\n"
            begin += f"    result = bpf_map_lookup_elem(mat_map_2, &i);\n"
            begin += f"    mat_2[i] = *(int *)result;\n"

    return begin


def get_end(mat_dim: int, rolled: bool):
    end = ""

    if rolled:
        end += """
    // Write back to map
    for (i = 0; i < MAT_SIZE; i++) {
        bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    }
"""

    else:
        for i in range(mat_dim):
            end += f"    i = {i};\n"
            end += f"    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);\n"

    end += "    return 0;\n"
    end += "}\n"

    return end


def get_middle(mat_dim: int, rolled: bool):
    middle = ""

    if rolled:
        middle += """
    // Do multiplication
    for (ii = 0; i < MAT_DIM; ii += IB) {
        for (kk = 0; kk < MAT_DIM; kk += KB) {
            for (j = 0; j < MAT_DIM; j += 2) {
                for (i = ii; i < ii + IB; i += 2) {
                    if (kk == 0) 
                        acc00 = acc01 = acc10 = acc11 = 0;
                    else {
                        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
                        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
                        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
                        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
                    }
                    for (k = kk; k < kk + KB; k++) {
                        acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
                        acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
                        acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
                        acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];
                    }
                    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
                    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
                    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
                    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
                }
            }
        }
    }
"""

    else:
        for ii in range(0, mat_dim, IB_SIZE):
            middle += f"    ii = {ii};\n"
            for kk in range(0, mat_dim, KB_SIZE):
                middle += f"    kk = {kk};\n"
                for j in range(0, mat_dim, 2):
                    middle += f"    j = {j};\n"
                    for i in range(ii, ii + IB_SIZE, 2):
                        middle += f"    {i};\n"
                        if kk == 0:
                            middle += "    acc00 = acc01 = acc10 = acc11 = 0;\n"
                        else:
                            middle += """
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
"""
                        for k in range(kk, kk + KB_SIZE):
                            middle += f"""
    k = {k};
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];
"""

                        middle += """
    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
"""

    return middle


def main():
    assert len(sys.argv) == 2
    name = sys.argv[1]
    mat_dim = 0
    match name:
        case "small_matmul":
            mat_dim = 8
        case "medium_matmul":
            mat_dim = 12
        case "big_matmul":
            mat_dim = 16
        case "huge_matmul":
            mat_dim = 20
        case _:
            raise Exception(f"bad argument")

    if mat_dim % IB_SIZE or mat_dim % KB_SIZE:
        raise Exception(
            f"mat_dim: {mat_dim} must be divisible by both ib={IB_SIZE} and kb={KB_SIZE}"
        )

    # unrolled
    begin = get_begin(mat_dim, rolled=False)
    middle = get_middle(mat_dim, rolled=False)
    end = get_end(mat_dim, rolled=False)
    contents = begin + middle + end
    with open(f"unrolled_{name}_cache_optimal.bpf.c", "w") as f:
        f.write(contents)

    # rolled
    begin = get_begin(mat_dim, rolled=True)
    middle = get_middle(mat_dim, rolled=True)
    end = get_end(mat_dim, rolled=True)
    contents = begin + middle + end
    with open(f"rolled_{name}_cache_optimal.bpf.c", "w") as f:
        f.write(contents)


if __name__ == "__main__":
    main()

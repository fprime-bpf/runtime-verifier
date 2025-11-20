#include "bpf_shim.h"

#define MAT_DIM 4
#define MAT_SIZE (MAT_DIM * MAT_DIM)
#define IB 4
#define KB 4

int main() {
    void *mat_map_1 = MAP_BY_FD(0), *mat_map_2 = MAP_BY_FD(1), *mat_map_res = MAP_BY_FD(2), *result;
    float mat_1[MAT_SIZE], mat_2[MAT_SIZE], mat_res[MAT_SIZE];
    int i, j, k, ii, kk;
    float acc00, acc01, acc10, acc11;

    // Read in 2 matrices
    for (i = 0; i < MAT_SIZE; i++) {
        result = bpf_map_lookup_elem(mat_map_1, &i);
        mat_1[i] = *(float *)result;

        result = bpf_map_lookup_elem(mat_map_2, &i);
        mat_2[i] = *(float *)result;
    }

    // Do multiplication
    for (ii = 0; ii < N; ii += IB)
    {
        for (kk = 0; kk < N; kk += KB)
        {
            for (j = 0; j < N; j += 2)
            {
                for (i = ii; i < ii + IB; i += 2)
                {
                    if (kk == 0)
                        acc00 = acc01 = acc10 = acc11 = 0;
                    else
                    {
                        acc00 = mat_res[i + 0][j + 0];
                        acc01 = mat_res[i + 0][j + 1];
                        acc10 = mat_res[i + 1][j + 0];
                        acc11 = mat_res[i + 1][j + 1];
                    }
                    for (k = kk; k < kk + KB; k++)
                    {
                        acc00 += mat_2[k][j + 0] * mat_1[i + 0][k];
    	                acc01 += mat_2[k][j + 1] * mat_1[i + 0][k];
    	                acc10 += mat_2[k][j + 0] * mat_1[i + 1][k];
    	                acc11 += mat_2[k][j + 1] * mat_1[i + 1][k];
                    }
                    mat_res[i + 0][j + 0] = acc00;
                    mat_res[i + 0][j + 1] = acc01;
                    mat_res[i + 1][j + 0] = acc10;
                    mat_res[i + 1][j + 1] = acc11;
                }
            }
        }
    }

    // Write back to map
    for (i = 0; i < MAT_SIZE; i++) {
        bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    }
    return 0;
}

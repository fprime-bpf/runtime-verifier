
#include "bpf_shim.h"
#define MAT_DIM 8
#define MAT_SIZE (MAT_DIM * MAT_DIM)
#define IB 4
int main() {
    void *mat_map_1 = MAP_BY_FD(0), *mat_map_2 = MAP_BY_FD(1), *mat_map_res = MAP_BY_FD(2), *result;
    int mat_1[MAT_SIZE], mat_2[MAT_SIZE], mat_res[MAT_SIZE];
    long i, j, k, ii, kk;
    int acc00, acc01, acc10, acc11;

    i = 0;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 1;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 2;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 3;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 4;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 5;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 6;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 7;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 8;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 9;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 10;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 11;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 12;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 13;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 14;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 15;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 16;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 17;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 18;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 19;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 20;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 21;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 22;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 23;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 24;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 25;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 26;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 27;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 28;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 29;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 30;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 31;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 32;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 33;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 34;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 35;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 36;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 37;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 38;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 39;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 40;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 41;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 42;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 43;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 44;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 45;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 46;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 47;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 48;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 49;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 50;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 51;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 52;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 53;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 54;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 55;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 56;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 57;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 58;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 59;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 60;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 61;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 62;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 63;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    ii = 0;
    j = 0;
    i = 0;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;
    i = 0;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;
    i = 0;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;
    i = 0;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    ii = 4;
    j = 0;
    i = 4;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;
    i = 4;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;
    i = 4;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;
    i = 4;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;
    acc00 = acc01 = acc10 = acc11 = 0;

k = 0;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 1;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 2;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 3;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 4;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 5;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 6;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

k = 7;
acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 0;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 1;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 2;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 3;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 4;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 5;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 6;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 7;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    return 0;
}

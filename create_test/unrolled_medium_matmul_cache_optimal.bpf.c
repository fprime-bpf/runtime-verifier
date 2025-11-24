
#include "bpf_shim.h"
#define MAT_DIM 12
#define MAT_SIZE (MAT_DIM * MAT_DIM)
#define IB 4
#define KB 4
int main() {
    void *mat_map_1 = MAP_BY_FD(0), *mat_map_2 = MAP_BY_FD(1), *mat_map_res = MAP_BY_FD(2), *result;
    int mat_1[MAT_SIZE], mat_2[MAT_SIZE], mat_res[MAT_SIZE];
    int i, j, k, ii, kk;
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
    i = 64;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 65;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 66;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 67;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 68;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 69;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 70;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 71;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 72;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 73;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 74;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 75;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 76;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 77;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 78;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 79;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 80;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 81;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 82;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 83;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 84;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 85;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 86;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 87;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 88;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 89;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 90;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 91;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 92;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 93;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 94;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 95;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 96;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 97;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 98;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 99;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 100;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 101;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 102;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 103;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 104;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 105;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 106;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 107;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 108;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 109;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 110;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 111;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 112;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 113;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 114;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 115;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 116;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 117;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 118;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 119;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 120;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 121;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 122;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 123;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 124;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 125;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 126;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 127;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 128;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 129;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 130;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 131;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 132;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 133;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 134;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 135;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 136;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 137;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 138;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 139;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 140;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 141;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 142;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 143;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    ii = 0;
    kk = 0;
    j = 0;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 4;
    j = 0;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    j = 8;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    j = 10;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    kk = 8;
    j = 0;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;

    i = 0;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 2;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    ii = 4;
    kk = 0;
    j = 0;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 4;
    j = 0;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    j = 8;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    j = 10;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    kk = 8;
    j = 0;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
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
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;

    i = 4;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 6;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    ii = 8;
    kk = 0;
    j = 0;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 4;
    j = 0;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    j = 8;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    j = 10;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

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
    kk = 8;
    j = 0;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;

    i = 8;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;

    i = 10;
    if (kk == 0) {
        acc00 = acc01 = acc10 = acc11 = 0;
    }
    else {
        acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
        acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
        acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
        acc11 = mat_res[(i+1) * MAT_DIM + j + 1];
    }

    k = 8;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 9;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 10;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 11;
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
    i = 8;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 9;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 10;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 11;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    return 0;
}

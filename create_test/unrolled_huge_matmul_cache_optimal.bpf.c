
#include "bpf_shim.h"
#define MAT_DIM 20
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
    i = 144;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 145;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 146;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 147;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 148;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 149;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 150;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 151;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 152;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 153;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 154;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 155;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 156;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 157;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 158;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 159;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 160;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 161;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 162;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 163;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 164;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 165;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 166;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 167;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 168;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 169;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 170;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 171;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 172;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 173;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 174;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 175;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 176;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 177;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 178;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 179;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 180;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 181;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 182;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 183;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 184;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 185;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 186;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 187;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 188;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 189;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 190;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 191;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 192;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 193;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 194;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 195;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 196;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 197;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 198;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 199;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 200;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 201;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 202;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 203;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 204;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 205;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 206;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 207;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 208;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 209;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 210;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 211;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 212;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 213;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 214;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 215;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 216;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 217;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 218;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 219;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 220;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 221;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 222;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 223;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 224;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 225;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 226;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 227;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 228;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 229;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 230;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 231;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 232;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 233;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 234;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 235;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 236;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 237;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 238;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 239;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 240;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 241;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 242;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 243;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 244;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 245;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 246;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 247;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 248;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 249;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 250;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 251;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 252;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 253;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 254;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 255;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 256;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 257;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 258;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 259;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 260;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 261;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 262;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 263;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 264;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 265;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 266;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 267;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 268;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 269;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 270;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 271;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 272;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 273;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 274;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 275;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 276;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 277;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 278;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 279;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 280;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 281;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 282;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 283;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 284;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 285;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 286;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 287;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 288;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 289;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 290;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 291;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 292;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 293;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 294;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 295;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 296;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 297;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 298;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 299;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 300;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 301;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 302;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 303;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 304;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 305;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 306;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 307;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 308;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 309;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 310;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 311;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 312;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 313;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 314;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 315;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 316;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 317;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 318;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 319;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 320;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 321;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 322;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 323;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 324;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 325;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 326;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 327;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 328;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 329;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 330;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 331;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 332;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 333;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 334;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 335;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 336;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 337;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 338;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 339;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 340;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 341;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 342;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 343;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 344;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 345;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 346;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 347;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 348;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 349;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 350;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 351;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 352;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 353;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 354;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 355;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 356;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 357;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 358;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 359;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 360;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 361;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 362;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 363;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 364;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 365;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 366;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 367;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 368;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 369;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 370;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 371;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 372;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 373;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 374;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 375;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 376;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 377;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 378;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 379;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 380;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 381;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 382;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 383;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 384;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 385;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 386;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 387;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 388;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 389;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 390;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 391;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 392;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 393;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 394;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 395;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 396;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 397;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 398;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    i = 399;
    result = bpf_map_lookup_elem(mat_map_1, &i);
    mat_1[i] = *(int *)result;
    result = bpf_map_lookup_elem(mat_map_2, &i);
    mat_2[i] = *(int *)result;
    ii = 0;
    kk = 0;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 4;
    j = 0;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 12;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 14;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 16;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 18;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 12;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 14;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 16;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 18;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    kk = 12;
    j = 0;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 16;
    j = 0;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 0;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 2;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 4;
    j = 0;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 12;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 14;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 16;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 18;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 12;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 14;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 16;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 18;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    kk = 12;
    j = 0;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 16;
    j = 0;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 4;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 6;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;
    i = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;
    i = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;
    i = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;
    i = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;
    i = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 8;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 4;
    j = 0;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 12;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 14;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 16;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 18;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 12;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 14;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 16;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 18;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    kk = 12;
    j = 0;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 16;
    j = 0;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 8;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 10;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    ii = 12;
    kk = 0;
    j = 0;
    i = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;
    i = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;
    i = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;
    i = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;
    i = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;
    i = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 12;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 4;
    j = 0;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 12;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 14;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 16;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 18;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 12;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 14;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 16;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 18;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    kk = 12;
    j = 0;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 16;
    j = 0;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 12;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 14;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    ii = 16;
    kk = 0;
    j = 0;
    i = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;
    i = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;
    i = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;
    i = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;
    i = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;
    i = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 16;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;
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

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 4;
    j = 0;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 12;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 14;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 16;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 18;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 12;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 14;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 16;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    j = 18;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

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
    kk = 12;
    j = 0;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 12;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 13;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 14;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 15;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    kk = 16;
    j = 0;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 2;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 4;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 6;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 8;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 10;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 12;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 14;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 16;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    j = 18;
    i = 16;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    mat_res[(i + 0) * MAT_DIM + j + 0] = acc00;
    mat_res[(i + 0) * MAT_DIM + j + 1] = acc01;
    mat_res[(i + 1) * MAT_DIM + j + 0] = acc10;
    mat_res[(i + 1) * MAT_DIM + j + 1] = acc11;
    i = 18;

    acc00 = mat_res[(i+0) * MAT_DIM + j + 0];
    acc01 = mat_res[(i+0) * MAT_DIM + j + 1];
    acc10 = mat_res[(i+1) * MAT_DIM + j + 0];
    acc11 = mat_res[(i+1) * MAT_DIM + j + 1];

    k = 16;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 17;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 18;
    acc00 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 0) * MAT_DIM + k];
    acc01 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 0) * MAT_DIM + k];
    acc10 += mat_2[k * MAT_DIM + j + 0] * mat_1[(i + 1) * MAT_DIM + k];
    acc11 += mat_2[k * MAT_DIM + j + 1] * mat_1[(i + 1) * MAT_DIM + k];

    k = 19;
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
    i = 12;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 13;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 14;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 15;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 16;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 17;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 18;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    i = 19;
    bpf_map_update_elem(mat_map_res, &i, &mat_res[i], 0);
    return 0;
}

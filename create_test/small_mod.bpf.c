
#include "bpf_shim.h"
#define ARR_SIZE 8
int main() {
    void *mat_map_1 = MAP_BY_FD(0), *result;
    int mat[ARR_SIZE], mod = 0, i = 0;

    i = 0;
    mat[0] = *(int *)bpf_map_lookup_elem(mat_map_1, &i);
    i = 1;
    mat[1] = *(int *)bpf_map_lookup_elem(mat_map_1, &i);
    i = 2;
    mat[2] = *(int *)bpf_map_lookup_elem(mat_map_1, &i);
    i = 3;
    mat[3] = *(int *)bpf_map_lookup_elem(mat_map_1, &i);
    i = 4;
    mat[4] = *(int *)bpf_map_lookup_elem(mat_map_1, &i);
    i = 5;
    mat[5] = *(int *)bpf_map_lookup_elem(mat_map_1, &i);
    i = 6;
    mat[6] = *(int *)bpf_map_lookup_elem(mat_map_1, &i);
    i = 7;
    mat[7] = *(int *)bpf_map_lookup_elem(mat_map_1, &i);

    return 0;
}

import random
import sys

def get_begin(arr_size: int):
    return f"""
#define ARR_SIZE {arr_size}
int main() {{
    int arr[ARR_SIZE];
    int mod = 0;

    """

def get_end():
    return """
    return mod;
}
"""


def get_middle(arr_size: int):
    middle = ''
    for i in range(arr_size):
        middle += f"    arr[{i}] = {random.randint(1, 1000)};\n"

    for i in range(arr_size):
        middle += f"    mod = (mod + arr[{i}]) % 10;\n"

    return middle



def main():
    assert len(sys.argv) == 2
    name = sys.argv[1]
    filename = f"{name}.bpf.c"
    arr_size = 0
    match name:
        case "big_mod":
            arr_size = 128
        case  "huge_mod":
            arr_size = 512
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

import os
import argparse

def djb2_hash(string):
    hash_value = 5381
    for char in string:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        hash_value &= 0xFFFFFFFF
    return hash_value

def main():
    parser = argparse.ArgumentParser(
        description="Generate defs.h with djb2 hashes from ntdll API names"
    )

    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    input_path = os.path.join(base_dir, "..", "rsrc", "ntdll_api.txt")
    output_path = os.path.join(base_dir, "..", "src", "ntdll_def.h")

    with open(input_path, "r") as f:
        names = [line.strip() for line in f if line.strip()]

    with open(output_path, "w") as f:
        hash_value = djb2_hash("ntdll.dll")
        f.write(f"#define NTDLL_HASH 0x{hash_value:08X}\n")
        for name in sorted(set(names)):
            hash_value = djb2_hash(name)
            f.write(f"#define {name} 0x{hash_value:08X}\n")

    print(f"Generated: {output_path} ({len(names)} entries)")

if __name__ == "__main__":
    main()
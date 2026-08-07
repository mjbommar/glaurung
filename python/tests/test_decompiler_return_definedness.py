"""Real round-trip coverage for Thumb VFP results reaching LLIR returns."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow  # ty: ignore[unresolved-attribute]

_SOURCE = r"""
double return_double_after_integer(double value, int scale) {
    double result = -value;
    __asm__ volatile ("" : "+w"(result) : : "memory");
    volatile int residue = scale * 3 + 1;
    __asm__ volatile ("" : : "m"(residue) : "memory");
    return result;
}
"""

_WORKER = r"""
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef double (*candidate_fn)(double, int);

static uint64_t bits(double value) {
    uint64_t result;
    memcpy(&result, &value, sizeof(result));
    return result;
}

int main(int argc, char **argv) {
    if (argc != 3) return 90;
    void *original_so = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void *rebuilt_so = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!original_so || !rebuilt_so) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 91;
    }
    candidate_fn original = (candidate_fn)dlsym(
        original_so, "return_double_after_integer");
    candidate_fn rebuilt = (candidate_fn)dlsym(
        rebuilt_so, "return_double_after_integer");
    if (!original || !rebuilt) return 92;

    const double values[] = {0.0, -0.0, 1.5, -2.25, 65536.125};
    const int scales[] = {0, 1, -7, 1234567};
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        for (unsigned j = 0; j < sizeof(scales) / sizeof(scales[0]); ++j) {
            double expected = original(values[i], scales[j]);
            double actual = rebuilt(values[i], scales[j]);
            if (bits(expected) != bits(actual)) {
                fprintf(stderr,
                    "mismatch value_bits=%llx scale=%d expected=%llx actual=%llx\n",
                    (unsigned long long)bits(values[i]), scales[j],
                    (unsigned long long)bits(expected),
                    (unsigned long long)bits(actual));
                return 1;
            }
        }
    }
    return 0;
}
"""


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def test_thumb_vfp_result_survives_cfg_discovery_and_integer_residue(
    tmp_path: Path,
) -> None:
    """A decoded VNEG and the eventual d0 result must both reach emitted C."""
    compiler = "arm-linux-gnueabihf-gcc"
    objdump = "arm-linux-gnueabihf-objdump"
    qemu = "qemu-arm"
    missing = [tool for tool in (compiler, objdump, qemu) if shutil.which(tool) is None]
    if missing:
        pytest.skip(
            f"ARM hard-float integration tools are missing: {', '.join(missing)}"
        )

    source = tmp_path / "return_definedness.c"
    source.write_text(_SOURCE)
    original = tmp_path / "return_definedness-original.so"
    target_flags = [
        "-march=armv7-a",
        "-mfpu=vfpv3-d16",
        "-mfloat-abi=hard",
        "-mthumb",
    ]
    compiled = _run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-w",
            "-fno-stack-protector",
            *target_flags,
            "-o",
            str(original),
            str(source),
        ]
    )
    assert compiled.returncode == 0, compiled.stderr

    disassembled = _run([objdump, "-d", str(original)])
    assert disassembled.returncode == 0, disassembled.stderr
    function_asm = disassembled.stdout.split("<return_double_after_integer>:", 1)[1]
    function_asm = function_asm.split("\n\n", 1)[0]
    assert "vneg.f64\td0, d0" in function_asm, function_asm
    assert "add.w\tr0, r0, r0" in function_asm, function_asm
    assert function_asm.index("vneg.f64") < function_asm.index("add.w\tr0"), (
        function_asm
    )
    assert "bx\tlr" in function_asm, function_asm

    function = D.exported_functions(str(original))["return_double_after_integer"]
    recovered_code = D.decompiled_c(str(original), function)
    assert recovered_code is not None
    assert "arg0 = (-arg0);" in recovered_code, recovered_code
    assert "return arg0;" in recovered_code, recovered_code

    recovered_source = tmp_path / "return_definedness-recovered.c"
    recovered_source.write_text(recovered_code)
    recovered = tmp_path / "return_definedness-recovered.so"
    rebuilt = _run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-O2",
            "-w",
            *target_flags,
            "-o",
            str(recovered),
            str(recovered_source),
        ]
    )
    assert rebuilt.returncode == 0, f"{rebuilt.stderr}\n{recovered_code}"

    worker_source = tmp_path / "return_definedness-worker.c"
    worker_source.write_text(_WORKER)
    worker = tmp_path / "return_definedness-worker"
    worker_build = _run(
        [
            compiler,
            "-O2",
            *target_flags,
            "-o",
            str(worker),
            str(worker_source),
            "-ldl",
        ]
    )
    assert worker_build.returncode == 0, worker_build.stderr
    compared = _run(
        [
            qemu,
            "-L",
            "/usr/arm-linux-gnueabihf",
            str(worker),
            str(original),
            str(recovered),
        ]
    )
    assert compared.returncode == 0, f"{compared.stderr}\n{recovered_code}"

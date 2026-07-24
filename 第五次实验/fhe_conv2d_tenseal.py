#!/usr/bin/env python3
"""Single-input single-output 4x4/3x3 encrypted convolution demo.

The real backend uses TenSEAL when it is installed. The mock backend keeps the
same slot operations so the convolution layout can be verified without external
packages in this lab environment.
"""

from __future__ import annotations

import argparse
import math
from dataclasses import dataclass
from typing import List, Sequence, Tuple


Matrix = List[List[float]]

INPUT_4X4: Matrix = [
    [1.0, 2.0, 3.0, 4.0],
    [5.0, 6.0, 7.0, 8.0],
    [9.0, 10.0, 11.0, 12.0],
    [13.0, 14.0, 15.0, 16.0],
]

KERNEL_3X3: Matrix = [
    [1.0, 2.0, 3.0],
    [4.0, 5.0, 6.0],
    [7.0, 8.0, 9.0],
]

WINDOWS_PER_SIDE = 2
WINDOW_COUNT = WINDOWS_PER_SIDE * WINDOWS_PER_SIDE
KERNEL_SIZE = 3
BLOCK_SIZE = 16
SLOT_COUNT = WINDOW_COUNT * BLOCK_SIZE


def plain_conv2d_valid(image: Matrix, kernel: Matrix) -> Matrix:
    out_h = len(image) - len(kernel) + 1
    out_w = len(image[0]) - len(kernel[0]) + 1
    result = [[0.0 for _ in range(out_w)] for _ in range(out_h)]
    for oy in range(out_h):
        for ox in range(out_w):
            total = 0.0
            for ky in range(len(kernel)):
                for kx in range(len(kernel[0])):
                    total += image[oy + ky][ox + kx] * kernel[ky][kx]
            result[oy][ox] = total
    return result


def im2col_pack(image: Matrix) -> List[float]:
    slots = [0.0] * SLOT_COUNT
    block = 0
    for oy in range(WINDOWS_PER_SIDE):
        for ox in range(WINDOWS_PER_SIDE):
            base = block * BLOCK_SIZE
            idx = 0
            for ky in range(KERNEL_SIZE):
                for kx in range(KERNEL_SIZE):
                    slots[base + idx] = image[oy + ky][ox + kx]
                    idx += 1
            block += 1
    return slots


def repeated_kernel_mask(kernel: Matrix) -> List[float]:
    mask = [0.0] * SLOT_COUNT
    flat_kernel = [value for row in kernel for value in row]
    for block in range(WINDOW_COUNT):
        base = block * BLOCK_SIZE
        for idx, value in enumerate(flat_kernel):
            mask[base + idx] = value
    return mask


@dataclass
class MockCiphertext:
    slots: List[float]

    def mul_plain(self, plain: Sequence[float]) -> "MockCiphertext":
        return MockCiphertext([a * b for a, b in zip(self.slots, plain)])

    def add(self, other: "MockCiphertext") -> "MockCiphertext":
        return MockCiphertext([a + b for a, b in zip(self.slots, other.slots)])

    def rotate_left(self, steps: int) -> "MockCiphertext":
        steps %= len(self.slots)
        rotated = self.slots[steps:] + self.slots[:steps]
        return MockCiphertext(rotated)

    def decrypt(self) -> List[float]:
        return list(self.slots)


def reduce_block_sums(ciphertext: MockCiphertext) -> Tuple[MockCiphertext, int]:
    """Accumulate 9 product slots to the first slot of each 16-slot block."""
    acc = ciphertext
    rotations = 0
    for shift in (1, 2, 4, 8):
        acc = acc.add(acc.rotate_left(shift))
        rotations += 1
    return acc, rotations


def unpack_outputs(slots: Sequence[float]) -> Matrix:
    values = [slots[block * BLOCK_SIZE] for block in range(WINDOW_COUNT)]
    return [values[:WINDOWS_PER_SIDE], values[WINDOWS_PER_SIDE:]]


def encrypted_conv_mock(image: Matrix, kernel: Matrix) -> Tuple[Matrix, int]:
    encrypted = MockCiphertext(im2col_pack(image))
    products = encrypted.mul_plain(repeated_kernel_mask(kernel))
    reduced, rotations = reduce_block_sums(products)
    return unpack_outputs(reduced.decrypt()), rotations


def encrypted_conv_tenseal(image: Matrix, kernel: Matrix) -> Matrix:
    import tenseal as ts

    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60],
    )
    context.global_scale = 2**40
    context.generate_galois_keys()

    flat_kernel = [value for row in kernel for value in row]
    encrypted, windows_nb = ts.im2col_encoding(context, image, KERNEL_SIZE, KERNEL_SIZE, 1)
    if windows_nb != WINDOW_COUNT:
        raise ValueError(f"unexpected TenSEAL window count: {windows_nb}")
    encrypted_result = encrypted.conv2d_im2col([flat_kernel], windows_nb)
    decrypted = encrypted_result.decrypt()
    return [
        list(decrypted[:WINDOWS_PER_SIDE]),
        list(decrypted[WINDOWS_PER_SIDE:WINDOW_COUNT]),
    ]


def max_abs_error(left: Matrix, right: Matrix) -> float:
    return max(
        abs(a - b)
        for row_left, row_right in zip(left, right)
        for a, b in zip(row_left, row_right)
    )


def format_matrix(matrix: Matrix) -> str:
    return "[" + ", ".join(str([round(value, 6) for value in row]) for row in matrix) + "]"


def run_backend(backend: str) -> Tuple[str, Matrix, int | None]:
    if backend == "tenseal":
        return "tenseal", encrypted_conv_tenseal(INPUT_4X4, KERNEL_3X3), None
    if backend == "mock":
        output, rotations = encrypted_conv_mock(INPUT_4X4, KERNEL_3X3)
        return "mock", output, rotations

    try:
        return "tenseal", encrypted_conv_tenseal(INPUT_4X4, KERNEL_3X3), None
    except Exception as exc:
        print(f"TenSEAL backend unavailable, falling back to mock backend: {exc}")
        output, rotations = encrypted_conv_mock(INPUT_4X4, KERNEL_3X3)
        return "mock", output, rotations


def main() -> None:
    parser = argparse.ArgumentParser(description="4x4 input, 3x3 encrypted convolution")
    parser.add_argument(
        "--backend",
        choices=("auto", "tenseal", "mock"),
        default="auto",
        help="auto tries TenSEAL first and falls back to the local slot simulator",
    )
    parser.add_argument("--tolerance", type=float, default=1e-3)
    args = parser.parse_args()

    plain = plain_conv2d_valid(INPUT_4X4, KERNEL_3X3)
    backend, encrypted_output, rotations = run_backend(args.backend)
    error = max_abs_error(plain, encrypted_output)

    print(f"backend: {backend}")
    print(f"plain convolution:\n{format_matrix(plain)}")
    print(f"encrypted convolution decrypted:\n{format_matrix(encrypted_output)}")
    if rotations is not None:
        print(f"mock homomorphic rotations: {rotations}")
    print(f"max absolute error: {error:.6f}")
    print(f"verification: {'PASS' if math.isclose(error, 0.0, abs_tol=args.tolerance) else 'FAIL'}")

    if error > args.tolerance:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

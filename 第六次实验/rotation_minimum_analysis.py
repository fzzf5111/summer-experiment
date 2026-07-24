#!/usr/bin/env python3
"""Rotation-count analysis for the 4x4/3x3 encrypted convolution."""

from __future__ import annotations

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

IMAGE_WIDTH = 4
WINDOWS_PER_SIDE = 2
WINDOW_COUNT = WINDOWS_PER_SIDE * WINDOWS_PER_SIDE
KERNEL_SIZE = 3
IM2COL_BLOCK_SIZE = 16
IM2COL_SLOT_COUNT = WINDOW_COUNT * IM2COL_BLOCK_SIZE


@dataclass
class SlotCiphertext:
    slots: List[float]

    def rotate_left(self, steps: int) -> "SlotCiphertext":
        steps %= len(self.slots)
        return SlotCiphertext(self.slots[steps:] + self.slots[:steps])

    def mul_plain(self, plain: Sequence[float]) -> "SlotCiphertext":
        return SlotCiphertext([a * b for a, b in zip(self.slots, plain)])

    def add(self, other: "SlotCiphertext") -> "SlotCiphertext":
        return SlotCiphertext([a + b for a, b in zip(self.slots, other.slots)])


def plain_conv2d_valid(image: Matrix, kernel: Matrix) -> Matrix:
    result = [[0.0 for _ in range(WINDOWS_PER_SIDE)] for _ in range(WINDOWS_PER_SIDE)]
    for oy in range(WINDOWS_PER_SIDE):
        for ox in range(WINDOWS_PER_SIDE):
            result[oy][ox] = sum(
                image[oy + ky][ox + kx] * kernel[ky][kx]
                for ky in range(KERNEL_SIZE)
                for kx in range(KERNEL_SIZE)
            )
    return result


def flatten_image(image: Matrix) -> List[float]:
    return [value for row in image for value in row]


def direct_output_mask(weight: float) -> List[float]:
    mask = [0.0] * (IMAGE_WIDTH * IMAGE_WIDTH)
    for oy in range(WINDOWS_PER_SIDE):
        for ox in range(WINDOWS_PER_SIDE):
            mask[oy * IMAGE_WIDTH + ox] = weight
    return mask


def direct_row_major_conv(image: Matrix, kernel: Matrix) -> Tuple[Matrix, int]:
    encrypted = SlotCiphertext(flatten_image(image))
    accumulator = SlotCiphertext([0.0] * len(encrypted.slots))
    rotations = 0

    for ky in range(KERNEL_SIZE):
        for kx in range(KERNEL_SIZE):
            offset = ky * IMAGE_WIDTH + kx
            if offset == 0:
                aligned = encrypted
            else:
                aligned = encrypted.rotate_left(offset)
                rotations += 1
            weighted = aligned.mul_plain(direct_output_mask(kernel[ky][kx]))
            accumulator = accumulator.add(weighted)

    slots = accumulator.slots
    output = [
        [slots[0], slots[1]],
        [slots[IMAGE_WIDTH], slots[IMAGE_WIDTH + 1]],
    ]
    return output, rotations


def im2col_pack(image: Matrix) -> List[float]:
    slots = [0.0] * IM2COL_SLOT_COUNT
    block = 0
    for oy in range(WINDOWS_PER_SIDE):
        for ox in range(WINDOWS_PER_SIDE):
            base = block * IM2COL_BLOCK_SIZE
            idx = 0
            for ky in range(KERNEL_SIZE):
                for kx in range(KERNEL_SIZE):
                    slots[base + idx] = image[oy + ky][ox + kx]
                    idx += 1
            block += 1
    return slots


def repeated_kernel_mask(kernel: Matrix) -> List[float]:
    flat_kernel = [value for row in kernel for value in row]
    mask = [0.0] * IM2COL_SLOT_COUNT
    for block in range(WINDOW_COUNT):
        base = block * IM2COL_BLOCK_SIZE
        for idx, value in enumerate(flat_kernel):
            mask[base + idx] = value
    return mask


def im2col_conv(image: Matrix, kernel: Matrix) -> Tuple[Matrix, int]:
    encrypted = SlotCiphertext(im2col_pack(image))
    accumulator = encrypted.mul_plain(repeated_kernel_mask(kernel))
    rotations = 0

    for shift in (1, 2, 4, 8):
        accumulator = accumulator.add(accumulator.rotate_left(shift))
        rotations += 1

    values = [accumulator.slots[block * IM2COL_BLOCK_SIZE] for block in range(WINDOW_COUNT)]
    return [values[:WINDOWS_PER_SIDE], values[WINDOWS_PER_SIDE:]], rotations


def matrices_close(left: Matrix, right: Matrix, tolerance: float = 1e-9) -> bool:
    return all(
        math.isclose(a, b, abs_tol=tolerance)
        for row_left, row_right in zip(left, right)
        for a, b in zip(row_left, row_right)
    )


def format_matrix(matrix: Matrix) -> str:
    return "[" + ", ".join(str([round(value, 6) for value in row]) for row in matrix) + "]"


def main() -> None:
    plain = plain_conv2d_valid(INPUT_4X4, KERNEL_3X3)
    direct_output, direct_rotations = direct_row_major_conv(INPUT_4X4, KERNEL_3X3)
    im2col_output, im2col_rotations = im2col_conv(INPUT_4X4, KERNEL_3X3)

    direct_minimum = KERNEL_SIZE * KERNEL_SIZE - 1
    im2col_minimum = math.ceil(math.log2(KERNEL_SIZE * KERNEL_SIZE))
    ok = matrices_close(plain, direct_output) and matrices_close(plain, im2col_output)

    print("plain convolution:")
    print(format_matrix(plain))
    print()
    print("direct row-major packing:")
    print(f"  output: {format_matrix(direct_output)}")
    print(f"  rotations used: {direct_rotations}")
    print(f"  theoretical minimum under this layout: {direct_minimum}")
    print(f"  reaches minimum: {direct_rotations == direct_minimum}")
    print()
    print("im2col block packing:")
    print(f"  output: {format_matrix(im2col_output)}")
    print(f"  rotations used: {im2col_rotations}")
    print(f"  theoretical minimum under this layout: {im2col_minimum}")
    print(f"  reaches minimum: {im2col_rotations == im2col_minimum}")
    print()
    print(f"verification: {'PASS' if ok else 'FAIL'}")

    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

#include <seal/seal.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using Matrix = std::array<std::array<std::uint64_t, 2>, 2>;

constexpr std::size_t image_width = 4;
constexpr std::size_t kernel_size = 3;
constexpr std::size_t windows_per_side = 2;
constexpr std::size_t window_count = windows_per_side * windows_per_side;
constexpr std::size_t im2col_block_size = 16;

const std::array<std::array<std::uint64_t, 4>, 4> input_image{{
    {{1, 2, 3, 4}},
    {{5, 6, 7, 8}},
    {{9, 10, 11, 12}},
    {{13, 14, 15, 16}},
}};

const std::array<std::array<std::uint64_t, 3>, 3> kernel{{
    {{1, 2, 3}},
    {{4, 5, 6}},
    {{7, 8, 9}},
}};

Matrix plain_conv2d()
{
    Matrix output{};
    for (std::size_t oy = 0; oy < windows_per_side; ++oy)
    {
        for (std::size_t ox = 0; ox < windows_per_side; ++ox)
        {
            std::uint64_t total = 0;
            for (std::size_t ky = 0; ky < kernel_size; ++ky)
            {
                for (std::size_t kx = 0; kx < kernel_size; ++kx)
                {
                    total += input_image[oy + ky][ox + kx] * kernel[ky][kx];
                }
            }
            output[oy][ox] = total;
        }
    }
    return output;
}

std::vector<std::uint64_t> row_major_slots(std::size_t slot_count)
{
    std::vector<std::uint64_t> slots(slot_count, 0);
    for (std::size_t y = 0; y < image_width; ++y)
    {
        for (std::size_t x = 0; x < image_width; ++x)
        {
            slots[y * image_width + x] = input_image[y][x];
        }
    }
    return slots;
}

std::vector<std::uint64_t> direct_mask(std::size_t slot_count, std::uint64_t weight)
{
    std::vector<std::uint64_t> mask(slot_count, 0);
    for (std::size_t oy = 0; oy < windows_per_side; ++oy)
    {
        for (std::size_t ox = 0; ox < windows_per_side; ++ox)
        {
            mask[oy * image_width + ox] = weight;
        }
    }
    return mask;
}

std::vector<std::uint64_t> im2col_slots(std::size_t slot_count)
{
    std::vector<std::uint64_t> slots(slot_count, 0);
    std::size_t block = 0;
    for (std::size_t oy = 0; oy < windows_per_side; ++oy)
    {
        for (std::size_t ox = 0; ox < windows_per_side; ++ox)
        {
            const std::size_t base = block * im2col_block_size;
            std::size_t idx = 0;
            for (std::size_t ky = 0; ky < kernel_size; ++ky)
            {
                for (std::size_t kx = 0; kx < kernel_size; ++kx)
                {
                    slots[base + idx] = input_image[oy + ky][ox + kx];
                    ++idx;
                }
            }
            ++block;
        }
    }
    return slots;
}

std::vector<std::uint64_t> repeated_kernel_mask(std::size_t slot_count)
{
    std::vector<std::uint64_t> mask(slot_count, 0);
    for (std::size_t block = 0; block < window_count; ++block)
    {
        const std::size_t base = block * im2col_block_size;
        std::size_t idx = 0;
        for (std::size_t ky = 0; ky < kernel_size; ++ky)
        {
            for (std::size_t kx = 0; kx < kernel_size; ++kx)
            {
                mask[base + idx] = kernel[ky][kx];
                ++idx;
            }
        }
    }
    return mask;
}

void print_matrix(const std::string &label, const Matrix &matrix)
{
    std::cout << label << ":\n";
    std::cout << "[[" << matrix[0][0] << ", " << matrix[0][1] << "], ["
              << matrix[1][0] << ", " << matrix[1][1] << "]]\n";
}

bool same_matrix(const Matrix &left, const Matrix &right)
{
    for (std::size_t y = 0; y < windows_per_side; ++y)
    {
        for (std::size_t x = 0; x < windows_per_side; ++x)
        {
            if (left[y][x] != right[y][x])
            {
                return false;
            }
        }
    }
    return true;
}

Matrix decode_direct_output(
    seal::BatchEncoder &encoder,
    seal::Decryptor &decryptor,
    const seal::Ciphertext &encrypted)
{
    seal::Plaintext plain;
    std::vector<std::uint64_t> decoded;
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, decoded);
    return Matrix{{
        {{decoded[0], decoded[1]}},
        {{decoded[image_width], decoded[image_width + 1]}},
    }};
}

Matrix decode_im2col_output(
    seal::BatchEncoder &encoder,
    seal::Decryptor &decryptor,
    const seal::Ciphertext &encrypted)
{
    seal::Plaintext plain;
    std::vector<std::uint64_t> decoded;
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, decoded);
    return Matrix{{
        {{decoded[0], decoded[im2col_block_size]}},
        {{decoded[2 * im2col_block_size], decoded[3 * im2col_block_size]}},
    }};
}

seal::Plaintext encode_mask(seal::BatchEncoder &encoder, const std::vector<std::uint64_t> &mask)
{
    seal::Plaintext plain_mask;
    encoder.encode(mask, plain_mask);
    return plain_mask;
}

std::pair<Matrix, int> encrypted_direct_conv(
    seal::BatchEncoder &encoder,
    seal::Encryptor &encryptor,
    seal::Evaluator &evaluator,
    seal::Decryptor &decryptor,
    const seal::GaloisKeys &galois_keys)
{
    seal::Plaintext plain_input;
    encoder.encode(row_major_slots(encoder.slot_count()), plain_input);

    seal::Ciphertext encrypted_input;
    encryptor.encrypt(plain_input, encrypted_input);

    seal::Ciphertext accumulator;
    bool has_accumulator = false;
    int rotations = 0;

    for (std::size_t ky = 0; ky < kernel_size; ++ky)
    {
        for (std::size_t kx = 0; kx < kernel_size; ++kx)
        {
            const std::size_t offset = ky * image_width + kx;
            seal::Ciphertext aligned;
            if (offset == 0)
            {
                aligned = encrypted_input;
            }
            else
            {
                evaluator.rotate_rows(encrypted_input, static_cast<int>(offset), galois_keys, aligned);
                ++rotations;
            }

            auto mask = encode_mask(encoder, direct_mask(encoder.slot_count(), kernel[ky][kx]));
            evaluator.multiply_plain_inplace(aligned, mask);

            if (has_accumulator)
            {
                evaluator.add_inplace(accumulator, aligned);
            }
            else
            {
                accumulator = aligned;
                has_accumulator = true;
            }
        }
    }

    return {decode_direct_output(encoder, decryptor, accumulator), rotations};
}

std::pair<Matrix, int> encrypted_im2col_conv(
    seal::BatchEncoder &encoder,
    seal::Encryptor &encryptor,
    seal::Evaluator &evaluator,
    seal::Decryptor &decryptor,
    const seal::GaloisKeys &galois_keys)
{
    seal::Plaintext plain_input;
    encoder.encode(im2col_slots(encoder.slot_count()), plain_input);

    seal::Ciphertext accumulator;
    encryptor.encrypt(plain_input, accumulator);

    auto mask = encode_mask(encoder, repeated_kernel_mask(encoder.slot_count()));
    evaluator.multiply_plain_inplace(accumulator, mask);

    int rotations = 0;
    for (int shift : {1, 2, 4, 8})
    {
        seal::Ciphertext rotated;
        evaluator.rotate_rows(accumulator, shift, galois_keys, rotated);
        evaluator.add_inplace(accumulator, rotated);
        ++rotations;
    }

    return {decode_im2col_output(encoder, decryptor, accumulator), rotations};
}

int main()
{
    using namespace seal;

    EncryptionParameters parms(scheme_type::bfv);
    const std::size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    if (!context.parameters_set())
    {
        throw std::runtime_error("invalid SEAL parameters");
    }

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);

    const Matrix plain = plain_conv2d();
    auto [direct_output, direct_rotations] =
        encrypted_direct_conv(encoder, encryptor, evaluator, decryptor, galois_keys);
    auto [im2col_output, im2col_rotations] =
        encrypted_im2col_conv(encoder, encryptor, evaluator, decryptor, galois_keys);

    print_matrix("plain convolution", plain);
    print_matrix("SEAL BFV direct row-major decrypted", direct_output);
    std::cout << "direct row-major rotations: " << direct_rotations << "\n";
    print_matrix("SEAL BFV im2col decrypted", im2col_output);
    std::cout << "im2col rotations: " << im2col_rotations << "\n";

    const int direct_minimum = static_cast<int>(kernel_size * kernel_size - 1);
    const int im2col_minimum = static_cast<int>(std::ceil(std::log2(kernel_size * kernel_size)));
    std::cout << "direct row-major theoretical minimum: " << direct_minimum << "\n";
    std::cout << "im2col theoretical minimum: " << im2col_minimum << "\n";

    const bool ok = same_matrix(plain, direct_output) && same_matrix(plain, im2col_output) &&
                    direct_rotations == direct_minimum && im2col_rotations == im2col_minimum;
    std::cout << "verification: " << (ok ? "PASS" : "FAIL") << "\n";
    return ok ? 0 : 1;
}

/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/internal/aead.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace ht::internal {

bool derive_aead_key_32(const std::string& psk,
                        const std::string& alg,
                        const std::string& ts,
                        const std::string& key_id,
                        const char* dir_tag,
                        std::string& key_out)
{
    std::string info = std::string("HT1:AEAD:") + alg + ":" + ts + ":" + key_id + ":" + dir_tag;
    unsigned int mac_len = 0;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned char* p = HMAC(EVP_sha256(),
                            psk.data(), (int)psk.size(),
                            (const unsigned char*)info.data(), info.size(),
                            mac, &mac_len);
    if (!p || mac_len != 32) return false;
    key_out.assign((const char*)mac, 32);
    return true;
}

bool aead_decrypt_body(std::string& plaintext,
                       const std::string& ciphertext,
                       const std::string& aead_alg,
                       const std::string& key32,
                       const std::string& nonce12,
                       const std::string& aad)
{
    const EVP_CIPHER* C = nullptr;
    if(aead_alg=="chacha20") C = EVP_chacha20_poly1305();
    else if(aead_alg=="aesgcm") C = EVP_aes_256_gcm();
    else return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return false;

    bool ok=false;
    do{
        if(1!=EVP_DecryptInit_ex(ctx, C, nullptr, nullptr, nullptr)) break;
        if(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr)) break;
        if(1!=EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                 (const unsigned char*)key32.data(),
                                 (const unsigned char*)nonce12.data())) break;

        int len=0;
        if(!aad.empty()){
            if(1!=EVP_DecryptUpdate(ctx, nullptr, &len,
                                    (const unsigned char*)aad.data(), (int)aad.size())) break;
        }

        if(ciphertext.size()<16) break;
        const std::size_t ct_len = ciphertext.size()-16;
        const unsigned char* tag = (const unsigned char*)ciphertext.data()+ct_len;
        if(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag)) break;

        plaintext.resize(ct_len);
        int outl=0, outl2=0;
        if(ct_len>0){
            if(1!=EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &outl,
                                    (const unsigned char*)ciphertext.data(), (int)ct_len)) break;
        }
        if(1!=EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext.data()+outl, &outl2)) break;
        plaintext.resize(outl+outl2);
        ok=true;
    } while(false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aead_encrypt_body(std::string& ciphertext,
                       const std::string& plaintext,
                       const std::string& aead_alg,
                       const std::string& key32,
                       const std::string& nonce12,
                       const std::string& aad)
{
    const EVP_CIPHER* C = nullptr;
    if(aead_alg=="chacha20") C = EVP_chacha20_poly1305();
    else if(aead_alg=="aesgcm") C = EVP_aes_256_gcm();
    else return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return false;

    bool ok=false;
    do{
        if(1!=EVP_EncryptInit_ex(ctx, C, nullptr, nullptr, nullptr)) break;
        if(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr)) break;
        if(1!=EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                                 (const unsigned char*)key32.data(),
                                 (const unsigned char*)nonce12.data())) break;

        int len=0;
        if(!aad.empty()){
            if(1!=EVP_EncryptUpdate(ctx, nullptr, &len,
                                    (const unsigned char*)aad.data(), (int)aad.size())) break;
        }

        ciphertext.resize(plaintext.size()+16);
        int outl=0, outl2=0;
        if(!plaintext.empty()){
            if(1!=EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext.data(), &outl,
                                    (const unsigned char*)plaintext.data(), (int)plaintext.size())) break;
        }
        if(1!=EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext.data()+outl, &outl2)) break;
        int total = outl+outl2;

        unsigned char tag[16];
        if(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) break;

        ciphertext.resize(total);
        ciphertext.append((const char*)tag, 16);
        ok=true;
    } while(false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

} // namespace ht::internal


#pragma once

// Following content is taken from https://github.com/ascon/ascon-c/blob/46f35c0a/crypto_aead_hash/asconav12/avx512/forceinline.h

#ifdef _MSC_VER
// MSVC
#define forceinline __forceinline

#elif defined(__GNUC__)
// GCC
#if defined(__cplusplus) && __cplusplus >= 201103L
#define forceinline inline __attribute__((__always_inline__))
#else
#define forceinline static inline
#endif

#elif defined(__CLANG__)
// Clang
#if __has_attribute(__always_inline__)
#define forceinline inline __attribute__((__always_inline__))
#else
#define forceinline inline
#endif

#else
// Others
#define forceinline inline

#endif

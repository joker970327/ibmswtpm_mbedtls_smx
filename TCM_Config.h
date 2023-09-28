#ifndef _TCM_CONFIG_HEADER_
#define _TCM_CONFIG_HEADER_

#include "./sm3.h"
#include "./sm4.h"

// #define TCM_MODE
// #define _SM2_SIGN_DEBUG
#define NDEBUG 
#define NO_LONGJMP

#if defined(TCG_SPI_SLAVE_IRQ)
#define TCG_SPI_SLAVE_0_IRQ TCG_SPI_SLAVE_IRQ
#elif defined(TCG_SPI_SLAVE_0_IRQ)
#define TCG_SPI_SLAVE_IRQ TCG_SPI_SLAVE_0_IRQ
#endif

#if defined(TCG_SPI_SLAVE_BASE)
#define TCG_SPI_SLAVE_0_BASE TCG_SPI_SLAVE_BASE
#elif defined(TCG_SPI_SLAVE_0_BASE)
#define TCG_SPI_SLAVE_BASE TCG_SPI_SLAVE_0_BASE
#endif

// /* System support */
// #define MBEDTLS_PLATFORM_C

// // enable mbedtls memory_buffer_alloc
// //    to static alloc memory
// #define MBEDTLS_PLATFORM_MEMORY
// #define MBEDTLS_MEMORY_BUFFER_ALLOC_C

// #define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
// #define MBEDTLS_PLATFORM_EXIT_ALT
// #define MBEDTLS_NO_PLATFORM_ENTROPY
// #define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
// #define MBEDTLS_PLATFORM_PRINTF_ALT

// /* mbed TLS modules */
// #define MBEDTLS_BIGNUM_C

// #define MBEDTLS_ECP_WINDOW_SIZE        2
// #define MBEDTLS_ECP_FIXED_POINT_OPTIM  0

// #undef MBEDTLS_NET_C
// #undef MBEDTLS_FS_IO
// #undef MBEDTLS_HAVE_TIME_DATE
// #undef MBEDTLS_HAVE_TIME

// #include "mbedtls/check_config.h"

#endif // _TCM_CONFIG_HEADER_
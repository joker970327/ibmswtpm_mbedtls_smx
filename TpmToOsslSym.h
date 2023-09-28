/********************************************************************************/
/*										*/
/*		Splice the OpenSSL() library into the TPM code.    		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: TpmToOsslSym.h 1671 2021-06-03 18:30:41Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016 - 2021				*/
/*										*/
/********************************************************************************/

/* B.2.3.2. TpmToOsslSym.h */
/* B.2.3.2.1. Introduction */
/* This header file is used to splice the OpenSSL() library into the TPM code. */
/* The support required of a library are a hash module, a block cipher module and portions of a big
   number library.  All of the library-dependent headers should have the same guard to that only the
   first one gets defined. */

#ifndef SYM_LIB_DEFINED
#define SYM_LIB_DEFINED
#define SYM_LIB_OSSL
// #include <openssl/aes.h>
#include <mbedtls/aes.h>
#if ALG_TDES
// #include <openssl/des.h>
#include <mbedtls/des.h>
#endif

#if ALG_SM4
// #   if defined(OPENSSL_NO_SM4) || OPENSSL_VERSION_NUMBER < 0x10101010L
// #       undef ALG_SM4
// #       define ALG_SM4  ALG_NO
// #   elif OPENSSL_VERSION_NUMBER >= 0x10200000L
// #       include <openssl/sm4.h>
// #   else
// // OpenSSL 1.1.1 keeps smX.h headers in the include/crypto directory,
// // and they do not get installed as part of the libssl package

// #       define SM4_KEY_SCHEDULE  32

// typedef struct SM4_KEY_st {
//     uint32_t rk[SM4_KEY_SCHEDULE];
// } SM4_KEY;

// int SM4_set_key(const uint8_t *key, SM4_KEY *ks);
// void SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);
// void SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);
// #   endif // OpenSSL < 1.2

#include "../sm4_src/sm4.h"

#endif // ALG_SM4

#if ALG_CAMELLIA
#include <mbedtls/camellia.h>
// #include <openssl/camellia.h>
#endif
// #include <openssl/bn.h>
// #include <openssl/ossl_typ.h>

/* B.2.2.3.2.	Links to the OpenSSL symmetric algorithms */
// The Crypt functions that call the block encryption function use the parameters in the order:
// a)	keySchedule
// b)	in buffer
// c) out buffer Since open SSL uses the order in encryptoCall_t above, need to swizzle the values
// to the order required by the library.

#define _MBEDTLS_ENCRYPT_CODE 1
#define _MBEDTLS_DECRYPT_CODE 0

#define SWIZZLE_ENC(keySchedule, in, out)					\
    (void *)(keySchedule),_MBEDTLS_ENCRYPT_CODE, (const BYTE *)(in), (BYTE *)(out) 

#define SWIZZLE_DEC(keySchedule, in, out)					\
    (void *)(keySchedule),_MBEDTLS_DECRYPT_CODE, (const BYTE *)(in), (BYTE *)(out) 

// Define the order of parameters to the library functions that do block encryption and decryption.

typedef void(*TpmCryptSetSymKeyCall_t)(
				       void *keySchedule,
                       int mode,
				       const BYTE  *in,
				       BYTE        *out
				       );

#define SYM_ALIGNMENT   RADIX_BYTES

/* B.2.2.3.3.	Links to the OpenSSL AES code */
/* Macros to set up the encryption/decryption key schedules */

#define TpmCryptSetEncryptKeyAES(key, keySizeInBits, schedule)		\
    mbedtls_aes_setkey_enc((tpmKeyScheduleAES *)(schedule),(key), (keySizeInBits) )
#define TpmCryptSetDecryptKeyAES(key, keySizeInBits, schedule)		\
    mbedtls_aes_setkey_dec((tpmKeyScheduleAES *)(schedule),(key), (keySizeInBits) )

/* Macros to alias encryption calls to specific algorithms. This should be used
   sparingly. Currently, only used by CryptSym.c and CryptRand.c */
/* When using these calls, to call the AES block encryption code, the caller should use:
   TpmCryptEncryptAES(SWIZZLE(keySchedule, in, out)); */

#define TpmCryptEncryptAES          mbedtls_aes_crypt_ecb // AES_encrypt
#define TpmCryptDecryptAES          mbedtls_aes_crypt_ecb // AES_decrypt
#define tpmKeyScheduleAES           mbedtls_aes_context //AES_KEY

/* B.2.2.3.4.	Links to the OpenSSL DES code */

#if ALG_TDES
#include "TpmToOsslDesSupport_fp.h"
#endif

#define TpmCryptSetEncryptKeyTDES(key, keySizeInBits, schedule)		\
    mbedtls_des3_set3key_enc((tpmKeyScheduleTDES *)(schedule), (key))//, (keySizeInBits), )
#define TpmCryptSetDecryptKeyTDES(key, keySizeInBits, schedule)		\
    mbedtls_des3_set3key_dec((tpmKeyScheduleTDES *)(schedule), (key))//, (keySizeInBits), )

/* Macros to alias encryption calls to specific algorithms. This should be used
   sparingly. Currently, only used by CryptRand.c */

#define TpmCryptEncryptTDES         mbedtls_des3_crypt_ecb //TDES_encrypt
#define TpmCryptDecryptTDES         mbedtls_des3_crypt_ecb // TDES_decrypt
#define tpmKeyScheduleTDES          mbedtls_des3_context   //DES_key_schedule

/* B.2.2.3.5.	Links to the OpenSSL SM4 code */
/* Macros to set up the encryption/decryption key schedules */

#define TpmCryptSetEncryptKeySM4(key, keySizeInBits, schedule)	\
    sm4_setkey_enc( (tpmKeyScheduleSM4 *)(schedule), (key))
#define TpmCryptSetDecryptKeySM4(key, keySizeInBits, schedule)	\
    sm4_setkey_dec( (tpmKeyScheduleSM4 *)(schedule), (key))
/* Macros to alias encryption calls to specific algorithms. This should be used sparingly. */

#define TpmCryptEncryptSM4          SM4_encrypt
#define TpmCryptDecryptSM4          SM4_decrypt
#define tpmKeyScheduleSM4           sm4_context

/* B.2.2.3.6.	Links to the OpenSSL CAMELLIA code */
/* Macros to set up the encryption/decryption key schedules */

#define TpmCryptSetEncryptKeyCAMELLIA(key, keySizeInBits, schedule)	\
    mbedtls_camellia_setkey_enc((tpmKeyScheduleCAMELLIA *)(schedule), (key), (keySizeInBits))
#define TpmCryptSetDecryptKeyCAMELLIA(key, keySizeInBits, schedule)	\
    mbedtls_camellia_setkey_enc((tpmKeyScheduleCAMELLIA *)(schedule), (key), (keySizeInBits))

/* Macros to alias encryption calls to specific algorithms. This should be used sparingly. */

#define TpmCryptEncryptCAMELLIA          mbedtls_camellia_crypt_ecb //Camellia_encrypt
#define TpmCryptDecryptCAMELLIA          mbedtls_camellia_crypt_ecb //Camellia_decrypt
#define tpmKeyScheduleCAMELLIA           mbedtls_camellia_context //CAMELLIA_KEY

/* Forward reference */

// kgold typedef union tpmCryptKeySchedule_t tpmCryptKeySchedule_t;

/* This definition would change if there were something to report */
#define SymLibSimulationEnd()
#endif // SYM_LIB_DEFINED

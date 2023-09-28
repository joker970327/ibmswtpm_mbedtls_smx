/********************************************************************************/
/*										*/
/*	 		TPM to OpenSSL BigNum Shim Layer			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2022				*/
/*										*/
/********************************************************************************/

/* B.2.2.1. TpmToOsslMath.h */
/* B.2.2.1.1. Introduction */
/* This file contains the structure definitions used for ECC in the OpenSSL version of the
   code. These definitions would change, based on the library. The ECC-related structures that cross
   the TPM interface are defined in TpmTypes.h */

#ifndef MATH_LIB_DEFINED
#define MATH_LIB_DEFINED
#define MATH_LIB_OSSL

#include <mbedtls/bignum.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>

#define SYMMETRIC_ALIGNMENT RADIX_BYTES

// #include <openssl/bn.h>

/* B.2.2.2.2. Macros and Defines */

/* Allocate a local BIGNUM value. For the allocation, a bigNum structure is created as is a local
   BIGNUM. The bigNum is initialized and then the BIGNUM is set to reference the local value. */

#define BIG_VAR(name, bits)						\
    BN_VAR(name##Bn, (bits));						\
    mbedtls_mpi    name;                        \
    mbedtls_mpi_init(&name);            \
    BigInitialized(&name, BnInit(name##Bn,BYTES_TO_CRYPT_WORDS(sizeof(_##name##Bn.d))))

/* Allocate a BIGNUM and initialize with the values in a bigNum initializer */

#define BIG_INITIALIZED(name, initializer)				\
    mbedtls_mpi          name;          \
    mbedtls_mpi_init(&name);           \
    BigInitialized(&name, initializer)

typedef struct
{
    const ECC_CURVE_DATA    *C;     // the TPM curve values
    mbedtls_ecp_group                *G;     // group parameters
} OSSL_CURVE_DATA;
typedef OSSL_CURVE_DATA      *bigCurve;
#define AccessCurveData(E)  ((E)->C)

/* Start and end a context that spans multiple ECC functions. This is used so that the group for the
   curve can persist across multiple frames. */

#define CURVE_INITIALIZED(name, initializer)				\
    OSSL_CURVE_DATA     _##name;					\
    bigCurve            name =  BnCurveInitialize(&_##name, initializer)

#define CURVE_FREE(name)               BnCurveFree(name)

/* This definition would change if there were something to report */
#define MathLibSimulationEnd()
#endif // MATH_LIB_DEFINED



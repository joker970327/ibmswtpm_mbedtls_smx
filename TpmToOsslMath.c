/********************************************************************************/
/*										*/
/*			 TPM to OpenSSL BigNum Shim Layer			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: TpmToOsslMath.c 1598 2020-03-27 21:59:49Z kgoldman $		*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2020				*/
/*										*/
/********************************************************************************/

/* B.2.3.2. TpmToOsslMath.c */
/* B.2.3.2.1. Introduction */

/* The functions in this file provide the low-level interface between the TPM code and the big
   number and elliptic curve math routines in OpenSSL. */
/* Most math on big numbers require a context. The context contains the memory in which OpenSSL
   creates and manages the big number values. When a OpenSSL math function will be called that
   modifies a BIGNUM value, that value must be created in an OpenSSL context. The first line of code
   in such a function must be: OSSL_ENTER(); and the last operation before returning must be
   OSSL_LEAVE(). OpenSSL variables can then be created with BnNewVariable(). Constant values to be
   used by OpenSSL are created from the bigNum values passed to the functions in this file. Space
   for the BIGNUM control block is allocated in the stack of the function and then it is initialized
   by calling BigInitialized(). That function sets up the values in the BIGNUM structure and sets
   the data pointer to point to the data in the bignum_t. This is only used when the value is known
   to be a constant in the called function. */
/* Because the allocations of constants is on the local stack and the OSSL_ENTER()/OSSL_LEAVE() pair
   flushes everything created in OpenSSL memory, there should be no chance of a memory leak. */


#include "Tpm.h"
#ifdef MATH_LIB_OSSL
#include "TpmToOsslMath_fp.h"
#include <stdio.h>
#include <stdlib.h>
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/error.h"
#include "mbedtls/ctr_drbg.h"

#if RADIX_BITS == 32
#       define DIV_FACTOR 4
#       define ADD_FACTOR 31
#elif RADIX_BITS == 64
#       define DIV_FACTOR 8
#       define ADD_FACTOR 63
#else
#       error "RADIX_BITS must either be 32 or 64"
#endif

/* B.2.3.2.3.1.	OsslToTpmBn() */
/* This function converts an OpenSSL BIGNUM to a TPM bignum. In this implementation it is assumed
   that OpenSSL uses a different control structure but the same data layout -- an array of
   native-endian words in little-endian order. */
/* Return Value	Meaning */
/* TRUE(1)	success */
/* FALSE(0)	failure because value will not fit or OpenSSL variable doesn't exist */
BOOL
OsslToTpmBn(
	    bigNum          bn,
	    mbedtls_mpi     *osslBn
	    )
{
    VERIFY(osslBn != NULL);
    // If the bn is NULL, it means that an output value pointer was NULL meaning that
    // the results is simply to be discarded.
    if(bn != NULL)
	{
	    size_t         i;
        size_t osslBn_bytes = mbedtls_mpi_size(osslBn);
        size_t left_b = ((osslBn_bytes % DIV_FACTOR) == 0) ? 0 : 1 ;
        size_t o2blen = mbedtls_mpi_size(osslBn) / DIV_FACTOR + left_b;
	    VERIFY(o2blen <= BnGetAllocated(bn));
	    // VERIFY((unsigned)osslBn->private_n <= BnGetAllocated(bn));

	    for(i = 0; i < o2blen; i++){
		    bn->d[i] = ((crypt_uword_t*)osslBn->private_p)[i];
        }
        
	    BnSetTop(bn, (int)o2blen);
	}
    return TRUE;
 Error:
    return FALSE;
}

/* B.2.3.2.3.2.	BigInitialized() */
/* This function initializes an OSSL BIGNUM from a TPM bigConst. Do not use this for values that are
   passed to OpenSLL when they are not declared as const in the function prototype. Instead, use
   BnNewVariable(). */
void
BigInitialized(
	       mbedtls_mpi             *toInit,
	       bigConst            initializer
	       )
{
    if(initializer == NULL){
	    FAIL(FATAL_ERROR_PARAMETER);
    }
    if(toInit == NULL || initializer == NULL){
	    return;
    }

    mbedtls_mpi_read_binary_le(toInit, (const unsigned char *)initializer->d, initializer->size * DIV_FACTOR);
    // mbedtls_mpi_read_binary(toInit, initializer->d, initializer->size * 4);

    return;
}

#if LIBRARY_COMPATIBILITY_CHECK

BOOL
MathLibraryCompatibilityCheck(
			      void
			      )
{
    mbedtls_mpi              osslTemp;
    mbedtls_mpi_init(&osslTemp);
    crypt_uword_t        i;
    BYTE                 test[] = {0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18,
				   0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
				   0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
				   0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    BN_VAR(tpmTemp, sizeof(test) * 8); // allocate some space for a test value
    //
    // Convert the test data to a bigNum
    BnFromBytes(tpmTemp, test, sizeof(test));
    // Convert the test data to an OpenSSL BIGNUM
    // BN_bin2bn(test, sizeof(test), osslTemp);
    mbedtls_mpi_read_binary(&osslTemp, test, sizeof(test));
    // Make sure the values are consistent
    VERIFY((int)osslTemp.private_n * sizeof(mbedtls_mpi_uint) == (int)tpmTemp->size * sizeof(crypt_uword_t));
    crypt_uword_t *osslTemp_p = (crypt_uword_t *)osslTemp.private_p;
    for(i = 0; i < tpmTemp->size; i++){

	    VERIFY(osslTemp_p[i] == tpmTemp->d[i]);
	    // VERIFY(osslTemp.private_p[i] == tpmTemp->d[i]);
    }
    return 1;
 Error:
    return 0;
}

#endif

/* B.2.3.2.3.3. BnModMult() */
/* Does multiply and divide returning the remainder of the divide. */
/* Return Value	Meaning */
/* TRUE(1)	success */
/* FALSE(0)	failure in operation */

LIB_EXPORT BOOL
BnModMult(
	  bigNum              result,
	  bigConst            op1,
	  bigConst            op2,
	  bigConst            modulus
	  )
{
    BOOL                OK = TRUE;
    mbedtls_mpi              bnResult;
    mbedtls_mpi_init(&bnResult);
    mbedtls_mpi              bnTemp;
    mbedtls_mpi_init(&bnTemp);

    BIG_INITIALIZED(bnOp1, op1);
    BIG_INITIALIZED(bnOp2, op2);
    BIG_INITIALIZED(bnMod, modulus);
    //
    VERIFY(!mbedtls_mpi_mul_mpi(&bnTemp, &bnOp1, &bnOp2));
    VERIFY(!mbedtls_mpi_div_mpi(NULL, &bnResult, &bnTemp, &bnMod));
    VERIFY(OsslToTpmBn(result, &bnResult));
    goto Exit;
 Error:
    OK = FALSE;
 Exit:
    return OK;
}

/* B.2.3.2.3.4. BnMult() */
/* Multiplies two numbers */
/* Return Value	Meaning */
/* TRUE(1)	success */
/* FALSE(0)	failure in operation */

LIB_EXPORT BOOL
BnMult(
       bigNum               result,
       bigConst             multiplicand,
       bigConst             multiplier
       )
{
    mbedtls_mpi              bnTemp;
    mbedtls_mpi_init(&bnTemp);
    BOOL                 OK = TRUE;
    BIG_INITIALIZED(bnA, multiplicand);
    BIG_INITIALIZED(bnB, multiplier);
    //
    VERIFY(!mbedtls_mpi_mul_mpi(&bnTemp, &bnA, &bnB));
    VERIFY(OsslToTpmBn(result, &bnTemp));
    goto Exit;
 Error:
    OK = FALSE;
 Exit:
    return OK;
}

/* B.2.3.2.3.5. BnDiv() */
/* This function divides two bigNum values. The function returns FALSE if there is an error in the
   operation. */
/* Return Value	Meaning */
/* TRUE(1)	success */
/* FALSE(0)	failure in operation */

LIB_EXPORT BOOL
BnDiv(
      bigNum               quotient,
      bigNum               remainder,
      bigConst             dividend,
      bigConst             divisor
      )
{
    mbedtls_mpi              bnQ;
    mbedtls_mpi_init(&bnQ);
    mbedtls_mpi              bnR;
    mbedtls_mpi_init(&bnR);
    BOOL                 OK = TRUE;

    if(BnEqualZero(divisor)){
	    FAIL(FATAL_ERROR_DIVIDE_ZERO);
    }

    BIG_INITIALIZED(bnDend, dividend);
    BIG_INITIALIZED(bnSor, divisor);

    if(quotient == NULL) {
        VERIFY(!mbedtls_mpi_mod_mpi(&bnR, &bnDend, &bnSor));
        VERIFY(OsslToTpmBn(remainder, &bnR));
    }
    else {
        VERIFY(!mbedtls_mpi_div_mpi(&bnQ, &bnR, &bnDend, &bnSor));
        VERIFY(OsslToTpmBn(quotient, &bnQ));
        VERIFY(OsslToTpmBn(remainder, &bnR));
    }

    goto Exit;
 Error:
    OK = FALSE;
 Exit:
    return OK;
}

#if ALG_RSA
/* B.2.3.2.3.6. BnGcd() */
/* Get the greatest common divisor of two numbers */
/* Return Value	Meaning */
/* TRUE(1)	success */
/* FALSE(0)	failure in operation */

LIB_EXPORT BOOL
BnGcd(
      bigNum      gcd,            // OUT: the common divisor
      bigConst    number1,        // IN:
      bigConst    number2         // IN:
      )
{
    mbedtls_mpi              bnGcd;
    mbedtls_mpi_init(&bnGcd);
    BOOL                 OK = TRUE;
    BIG_INITIALIZED(bn1, number1);
    BIG_INITIALIZED(bn2, number2);
    //
    VERIFY(!mbedtls_mpi_gcd(&bnGcd, &bn1, &bn2));
    VERIFY(OsslToTpmBn(gcd, &bnGcd));
    goto Exit;
 Error:
    OK = FALSE;
 Exit:
    return OK;
}

/* B.2.3.2.3.7. BnModExp() */
/* Do modular exponentiation using bigNum values. The conversion from a bignum_t to a bigNum is
   trivial as they are based on the same structure */
/* Return Value	Meaning */
/* TRUE(1)	success */
/* FALSE(0)	failure in operation */

LIB_EXPORT BOOL
BnModExp(
	 bigNum               result,         // OUT: the result
	 bigConst             number,         // IN: number to exponentiate
	 bigConst             exponent,       // IN:
	 bigConst             modulus         // IN:
	 )
{
    mbedtls_mpi              bnResult;
    mbedtls_mpi_init(&bnResult);
    BOOL                 OK = TRUE;
    BIG_INITIALIZED(bnN, number);
    BIG_INITIALIZED(bnE, exponent);
    BIG_INITIALIZED(bnM, modulus);
    //
    VERIFY(!mbedtls_mpi_exp_mod(&bnResult, &bnN, &bnE, &bnM, NULL));
    VERIFY(OsslToTpmBn(result, &bnResult));
    goto Exit;
 Error:
    OK = FALSE;
 Exit:
    return OK;
}

/* B.2.3.2.3.8. BnModInverse() */
/* Modular multiplicative inverse */
/* Return Value	Meaning */
/* TRUE(1)	success */
/* FALSE(0)	failure in operation */

LIB_EXPORT BOOL
BnModInverse(
	     bigNum               result,
	     bigConst             number,
	     bigConst             modulus
	     )
{
    mbedtls_mpi              bnResult;
    mbedtls_mpi_init(&bnResult);
    BOOL                 OK = TRUE;
    BIG_INITIALIZED(bnN, number);
    BIG_INITIALIZED(bnM, modulus);
    //
    VERIFY(!mbedtls_mpi_inv_mod(&bnResult, &bnN, &bnM));
    VERIFY(OsslToTpmBn(result, &bnResult));
    goto Exit;
 Error:
    OK = FALSE;
 Exit:
    return OK;
}

#endif // TPM_ALG_RSA

#if ALG_ECC

/* B.2.3.2.3.9. PointFromOssl() */
/* Function to copy the point result from an OSSL function to a bigNum */
/* Return Value	Meaning */
/* TRUE(1)	success */
/* FALSE(0)	failure in operation */
static BOOL
PointFromOssl(
	      bigPoint         pOut,      // OUT: resulting point
	      mbedtls_ecp_point        *pIn,       // IN: the point to return
	      bigCurve         E          // IN: the curve
	      )
{
    mbedtls_mpi    x;
    mbedtls_mpi_init(&x);
    mbedtls_mpi    y;
    mbedtls_mpi_init(&y);
    BOOL            OK = TRUE;
	// BnSetWord(pOut->z, 0);
    if(mbedtls_mpi_cmp_int(&pIn->private_Z,1) == 0){
        OsslToTpmBn(pOut->x, &pIn->private_X);
        OsslToTpmBn(pOut->y, &pIn->private_Y);
        BnSetWord(pOut->z, 1);
        OK = TRUE;
    }else{
        BnSetWord(pOut->z, 0);
        OK = FALSE;
    }
    return OK;
}

/* B.2.3.2.3.10. EcPointInitialized() */
/* Allocate and initialize a point. */
static void
EcPointInitialized(
           mbedtls_ecp_point *P,
		   pointConst          initializer,
		   bigCurve            E
		   )
{
    mbedtls_ecp_point_init(P);
    if(initializer != NULL)
	{
	    if(E == NULL){
		    FAIL(FATAL_ERROR_ALLOCATION);
        }
        BigInitialized(&P->private_X, initializer->x);
        BigInitialized(&P->private_Y, initializer->y);
        BigInitialized(&P->private_Z, initializer->z);
	    // P = EC_POINT_new(E->G);
	    // if(!EC_POINT_set_affine_coordinates_GFp(E->G, P, bnX, bnY, E->CTX))
		// P = NULL;
	}
    return ;
}

/* B.2.3.2.3.11. BnCurveInitialize() */
/* This function initializes the OpenSSL group definition */
/* It is a fatal error if groupContext is not provided. */
/* Return Values Meaning */
/* NULL the TPM_ECC_CURVE is not valid */
/* non-NULL points to a structure in groupContext */

LIB_EXPORT bigCurve
BnCurveInitialize(
		  bigCurve          E,           // IN: curve structure to initialize
		  TPM_ECC_CURVE     curveId      // IN: curve identifier
		  )
{
    const ECC_CURVE_DATA    *C = GetCurveData(curveId);
    if(C == NULL){
	    E = NULL;
    }
    if(E != NULL)
	{
	    // This creates the OpenSSL memory context that stays in effect as long as the
	    // curve (E) is defined.
	    // mbedtls_ecp_point                *P = NULL;
	    BIG_INITIALIZED(bnP, C->prime);
	    BIG_INITIALIZED(bnA, C->a);
	    BIG_INITIALIZED(bnB, C->b);
	    BIG_INITIALIZED(bnX, C->base.x);
	    BIG_INITIALIZED(bnY, C->base.y);
        BIG_INITIALIZED(bnZ, C->base.z);
	    BIG_INITIALIZED(bnN, C->order);
	    // BIG_INITIALIZED(bnH, C->h);
	    E->C = C;

        
        E->G = (mbedtls_ecp_group*)malloc(sizeof(mbedtls_ecp_group));

	    // initialize EC group, associate a generator point and initialize the point
	    // from the parameter data
	    // Create a group structure

	    // E->G = EC_GROUP_new_curve_GFp(bnP, bnA, bnB, CTX);
        mbedtls_ecp_group_init(E->G);
        mbedtls_mpi_copy(&E->G->P,           &bnP);
        mbedtls_mpi_copy(&E->G->A,           &bnA);
        mbedtls_mpi_copy(&E->G->B,           &bnB);
        mbedtls_mpi_copy(&E->G->N,           &bnN);

        mbedtls_mpi_copy(&E->G->G.private_X, &bnX);
        mbedtls_mpi_copy(&E->G->G.private_Y, &bnY);
        mbedtls_mpi_copy(&E->G->G.private_Z, &bnZ); // set 1
        
        E->G->pbits = mbedtls_mpi_bitlen(&bnP);
        E->G->nbits = mbedtls_mpi_bitlen(&bnN);
        
        E->G->private_h = 1;
        
        // E->G->private_T_size = 0;
	    VERIFY(E->G != NULL);
	    
	    // Allocate a point in the group that will be used in setting the
	    // generator. This is not needed after the generator is set.

	    // P = EC_POINT_new(E->G);
	    // VERIFY(P != NULL);
	    
	    // Need to use this in case Montgomery method is being used
	    // VERIFY(EC_POINT_set_affine_coordinates_GFp(E->G, P, bnX, bnY, CTX));
	    // Now set the generator
	    // VERIFY(EC_GROUP_set_generator(E->G, P, bnN, bnH));
	    
        // mbedtls_ecp_point_free(P);
	    goto Exit;
	Error:
        // mbedtls_ecp_point_free(P);
	    BnCurveFree(E);
	    E = NULL;
	}
 Exit:
    return E;

}

/* B.2.3.2.3.15.	BnCurveFree() */
/* This function will free the allocated components of the curve and end the frame in which the
   curve data exists */
LIB_EXPORT void
BnCurveFree(
	    bigCurve E
	    )
{
    if(E)
	{
        mbedtls_ecp_group_free(E->G);
	}
}

/* B.2.3.2.3.11. BnEccModMult() */
/* This functi2n does a point multiply of the form R = [d]S */
/* Return Values Meaning */
/* FALSE failure in operation; treat as result being point at infinity */

LIB_EXPORT BOOL
BnEccModMult(
	     bigPoint             R,         // OUT: computed point
	     pointConst           S,         // IN: point to multiply by 'd' (optional)
	     bigConst             d,         // IN: scalar for [d]S
	     bigCurve             E
	     )
{
    mbedtls_ecp_point            pR;
    mbedtls_ecp_point_init(&pR);
    mbedtls_ecp_point            pS;
    EcPointInitialized(&pS, S, E);

    BIG_INITIALIZED(bnD, d);
    mbedtls_ecp_point pZero;
    mbedtls_ecp_point_init(&pZero);
    mbedtls_mpi bnZero;
    mbedtls_mpi_init(&bnZero);

    if(S == NULL){
        mbedtls_ecp_muladd(E->G,&pR, &bnD, &E->G->G,&bnZero, &pZero);
    }
    else{
        mbedtls_ecp_muladd(E->G,&pR, &bnD, &pS,&bnZero, &pZero);
    }
    PointFromOssl(R, &pR, E);

    mbedtls_ecp_point_free(&pR);
    mbedtls_ecp_point_free(&pS);

    return !BnEqualZero(R->z);
}

/* B.2.3.2.3.13. BnEccModMult2() */
/* This function does a point multiply of the form R = [d]G + [u]Q */
/* FALSE	failure in operation; treat as result being point at infinity */

LIB_EXPORT BOOL
BnEccModMult2(
	      bigPoint             R,         // OUT: computed point
	      pointConst           S,         // IN: optional point
	      bigConst             d,         // IN: scalar for [d]S or [d]G
	      pointConst           Q,         // IN: second point
	      bigConst             u,         // IN: second scalar
	      bigCurve             E          // IN: curve
	      )
{
    mbedtls_ecp_point            pR;
    mbedtls_ecp_point_init(&pR);
    
    BIG_INITIALIZED(bnD, d);
    mbedtls_ecp_point            pS;
    EcPointInitialized(&pS, S, E);

    BIG_INITIALIZED(bnU, u);
    mbedtls_ecp_point            pQ;
    EcPointInitialized(&pQ, Q, E);
    
    if(S == NULL || S == (pointConst)&(AccessCurveData(E)->base)){
        mbedtls_ecp_muladd(E->G, &pR, &bnD, &E->G->G, &bnU, &pQ);
    }else{
        mbedtls_ecp_muladd(E->G, &pR, &bnD, &pS,      &bnU, &pQ);
    }
    PointFromOssl(R, &pR, E);
    
    mbedtls_mpi_free(&bnU);
    mbedtls_mpi_free(&bnD);
    mbedtls_ecp_point_free(&pR);
    mbedtls_ecp_point_free(&pS);
    mbedtls_ecp_point_free(&pQ);
    return !BnEqualZero(R->z);
}

/* B.2.3.2.4. BnEccAdd() */
/* This function does addition of two points. */
/* Return Values Meaning */
/* FALSE failure in operation; treat as result being point at infinity */
LIB_EXPORT BOOL
BnEccAdd(
	 bigPoint             R,         // OUT: computed point
	 pointConst           S,         // IN: first point
	 pointConst           Q,         // IN: second point
	 bigCurve             E          // IN: curve
	 )
{
    mbedtls_ecp_point            pR;
    mbedtls_ecp_point_init(&pR);

    mbedtls_ecp_point            pS;
    EcPointInitialized(&pS, S, E);
    mbedtls_mpi pM;
    mbedtls_mpi_init(&pM);
    mbedtls_mpi_lset(&pM,1);

    mbedtls_ecp_point            pQ;
    EcPointInitialized(&pQ, Q, E);
    mbedtls_mpi pN;
    mbedtls_mpi_init(&pN);
    mbedtls_mpi_lset(&pN,1);

    mbedtls_ecp_muladd(E->G,&pR, &pM, &pS, &pN, &pQ);

    PointFromOssl(R, &pR, E);
    
    mbedtls_mpi_free(&pM);
    mbedtls_mpi_free(&pN);
    mbedtls_ecp_point_free(&pR);
    mbedtls_ecp_point_free(&pS);
    mbedtls_ecp_point_free(&pQ);
    return !BnEqualZero(R->z);
}

#endif // ALG_ECC
#endif // MATH_LIB_OSSL

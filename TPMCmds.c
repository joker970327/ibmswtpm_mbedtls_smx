/********************************************************************************/
/*										*/
/*			 Main Simulator Entry Point		    		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: TPMCmds.c 1681 2022-04-14 21:45:26Z kgold $		*/
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
/*  (c) Copyright IBM Corp. and others, 2016 - 2019				*/
/*										*/
/********************************************************************************/

/* D.5 TPMCmds.c */
/* D.5.1. Description */
/* This file contains the entry point for the simulator. */
/* D.5.2. Includes, Defines, Data Definitions, and Function Prototypes */
#include "TpmBuildSwitches.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#ifdef TPM_WINDOWS
#include <windows.h>
#include <winsock.h>
#endif
#include "TpmTcpProtocol.h"
#include "Manufacture_fp.h"
#include "Platform_fp.h"
#include "Simulator_fp.h"
#ifdef TPM_WINDOWS
#include "TcpServer_fp.h"
#endif
#ifdef TPM_POSIX
#include "TcpServerPosix_fp.h"
#endif
#include "TpmProfile.h"		/* kgold */

#define PURPOSE							\
    "TPM Reference Simulator.\nCopyright Microsoft Corp.\n"
#define DEFAULT_TPM_PORT 2321

int verbose = 0;

/* D.5.3. Functions */
/* D.5.3.1. Usage() */
/* This function prints the proper calling sequence for the simulator. */

static void
Usage(
      char                *pszProgramName
      )
{
    fprintf(stderr, "%s", PURPOSE);
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s         - Starts the TPM server listening on port %d, %d\n",
	    pszProgramName, DEFAULT_TPM_PORT, DEFAULT_TPM_PORT+1);
    fprintf(stderr,  "%s -port PortNum - Starts the TPM server listening on port PortNum, PortNum+1\n",
	    pszProgramName);
    fprintf(stderr,  "%s -rm remanufacture the TPM before starting\n", pszProgramName);
    fprintf(stderr,  "%s -h      - This message\n", pszProgramName);
    fprintf(stderr,  "%s -v      - Verbose trace to trace.txt\n", pszProgramName);
    exit(1);
}



/* D.5.3.2. main() */
/* This is the main entry point for the simulator. */
/* It registers the interface and starts listening for clients */

// int sm3test()
// {
// 	unsigned char *input = "abc";
// 	int ilen = 3;
// 	unsigned char output[32];
// 	int i;
// 	sm3_context ctx;

// 	printf("Message:\n");
// 	printf("%s\n",input);

// 	sm3(input, ilen, output);
// 	printf("Hash:\n   ");
// 	for(i=0; i<32; i++)
// 	{
// 		printf("%02x",output[i]);
// 		if (((i+1) % 4 ) == 0) printf(" ");
// 	}
// 	printf("\n");

// 	printf("Message:\n");
// 	for(i=0; i < 16; i++)
// 		printf("abcd");
// 	printf("\n");

//     sm3_starts( &ctx );
// 	for(i=0; i < 16; i++)
// 		sm3_update( &ctx, (char *)"abcd", 4 );
//     sm3_finish(  output, &ctx );
//     memset( &ctx, 0, sizeof( sm3_context ) );

// 	printf("Hash:\n   ");
// 	for(i=0; i<32; i++)
// 	{
// 		printf("%02x",output[i]);
// 		if (((i+1) % 4 ) == 0) printf(" ");
// 	}
// 	printf("\n");
//     return 0;	
// }

// int sm4test()
// {
// 	unsigned char key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
// 	unsigned char input[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
// 	unsigned char output[16];
// 	sm4_context ctx;
// 	unsigned int i;

// 	//encrypt standard testing vector
// 	sm4_setkey_enc(&ctx,key);
// 	sm4_crypt_ecb(&ctx,1,16,input,output);
// 	for(i=0;i<16;i++)
// 		printf("%02x ", output[i]);
// 	printf("\n");

// 	//decrypt testing
// 	sm4_setkey_dec(&ctx,key);
// 	sm4_crypt_ecb(&ctx,0,16,output,output);
// 	for(i=0;i<16;i++)
// 		printf("%02x ", output[i]);
// 	printf("\n");

// 	//decrypt 1M times testing vector based on standards.
// 	i = 0;
// 	sm4_setkey_enc(&ctx,key);
// 	while (i<1000000)
//     {
// 		sm4_crypt_ecb(&ctx,1,16,input,input);
// 		i++;
//     }
// 	for(i=0;i<16;i++)
// 		printf("%02x ", input[i]);
// 	printf("\n");

//     return 0;
// }

int
main(
     int              argc,
     char            *argv[]
     )
{
    int		i;				/* argc iterator */
    int		irc;

    /* command line argument defaults */
    int manufacture = 0;
    int portNum = DEFAULT_TPM_PORT;
    int portNumPlat;
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */

    for (i=1 ; i<argc ; i++) {
	if (strcmp(argv[i],"-rm") == 0) {
	    manufacture = 1;
	}
	else if (strcmp(argv[i],"-port") == 0) {
	    i++;
	    if (i < argc) {
		portNum = atoi(argv[i]);
		if(portNum <=0 || portNum>65535) {
		    Usage(argv[0]);
		}
	    }
	    else {
		printf("Missing parameter for -port\n");
		Usage(argv[0]);
	    }
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    verbose = 1;
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    Usage(argv[0]);
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    Usage(argv[0]);
	}
    }
    printf("LIBRARY_COMPATIBILITY_CHECK is %s\n",
	   (LIBRARY_COMPATIBILITY_CHECK ? "ON" : "OFF"));
    // Enable NV memory
    _plat__NVEnable(NULL);
    
    if (manufacture || _plat__NVNeedsManufacture())
	{
	    printf("Manufacturing NV state...\n");
	    if(TPM_Manufacture(1) != 0)
		{
		    // if the manufacture didn't work, then make sure that the NV file doesn't
		    // survive. This prevents manufacturing failures from being ignored the
		    // next time the code is run.
		    _plat__NVDisable(1);
		    exit(1);
		}
	    // Coverage test - repeated manufacturing attempt
	    if(TPM_Manufacture(0) != 1)
		{
		    exit(2);
		}
	    // Coverage test - re-manufacturing
	    TPM_TearDown();
	    if(TPM_Manufacture(1) != 0)
		{
		    exit(3);
		}
	}
    // Disable NV memory
    _plat__NVDisable(0);
    /* power on the TPM  - kgold MS simulator comes up powered off */
    _rpc__Signal_PowerOn(FALSE);
    _rpc__Signal_NvOn();

	// sm3test();
	// sm4test();

    portNumPlat = portNum + 1;

    irc = StartTcpServer(&portNum, &portNumPlat);
    if (irc == 0) {
	return EXIT_SUCCESS;
    }
    else {
	return 4;
    }
}


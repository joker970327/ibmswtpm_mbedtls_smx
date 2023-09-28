#ifndef SM3_H
#define SM3_H

/**
 * \brief          SM3 context structure
 */
typedef struct
{
    unsigned long total[2];     /*!< number of bytes processed  */
    unsigned long state[8];     /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
sm3_context;


/**
 * \brief          SM3 context setup
 *
 * \param ctx      context to be initialized
 */
void sm3_starts( sm3_context *ctx );

/**
 * \brief          SM3 process buffer
 *
 * \param ctx      SM3 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sm3_update( sm3_context *ctx, unsigned char *input, int ilen );

/**
 * \brief          SM3 final digest
 *
 * \param ctx      SM3 context
 */
// void sm3_finish( sm3_context *ctx, unsigned char output[32] );
void sm3_finish(  sm3_context *ctx, unsigned char* output );

/**
 * \brief          Output = SM3( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SM3 checksum result
 */
void sm3( unsigned char *input, int ilen,
           unsigned char output[32]);

#endif /* sm3.h */

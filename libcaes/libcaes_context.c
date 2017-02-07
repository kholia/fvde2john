/*
 * AES de/encryption context functions
 *
 * Copyright (C) 2011-2016, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <byte_stream.h>
#include <memory.h>
#include <types.h>

#if defined( WINAPI )
#include <wincrypt.h>

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
#include <openssl/sha.h>

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )
#include <openssl/err.h>
#include <openssl/evp.h>

#endif

#include "libcaes_context.h"
#include "libcaes_crypt.h"
#include "libcaes_definitions.h"
#include "libcaes_key.h"
#include "libcaes_libcerror.h"
#include "libcaes_types.h"

#if !defined( LIBCAES_HAVE_AES_SUPPORT )
static int libcaes_tables_initialized = 0;
#endif

/* Creates a context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libcaes_context_initialize(
     libcaes_context_t **context,
     libcerror_error_t **error )
{
	libcaes_internal_context_t *internal_context = NULL;
	static char *function                        = "libcaes_context_initialize";

#if defined( WINAPI ) && ( WINVER >= 0x0600 )
	DWORD error_code                             = 0;
#endif

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( *context != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid context value already set.",
		 function );

		return( -1 );
	}
	internal_context = memory_allocate_structure(
	                    libcaes_internal_context_t );

	if( internal_context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create context.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     internal_context,
	     0,
	     sizeof( libcaes_internal_context_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear context.",
		 function );

		goto on_error;
	}
#if defined( WINAPI ) && ( WINVER >= 0x0600 )
	/* Request the AES crypt provider, fail back to the RSA crypt provider
	*/
	if( CryptAcquireContext(
	     &( internal_context->crypt_provider ),
	     NULL,
	     MS_ENH_RSA_AES_PROV,
	     PROV_RSA_AES,
	     0 ) == 0 )
	{
/* TODO fallback for XP
		if( CryptAcquireContext(
		     &( internal_context->crypt_provider ),
		     NULL,
		     MS_ENH_RSA_AES_PROV_XP,
		     PROV_RSA_AES,
		     CRYPT_NEWKEYSET ) == 0 )
*/
		error_code = GetLastError();

		libcerror_system_set_error(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 error_code,
		 "%s: unable to create AES crypt provider.",
		 function );

		return( -1 );
	}
	if( internal_context->crypt_provider == 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: unable to create AES crypt provider.",
		 function );

		return( -1 );
	}

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
	/* No additional initialization necessary */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )
	EVP_CIPHER_CTX_init(
	 &( internal_context->evp_context ) );

	if( EVP_CIPHER_CTX_set_padding(
	     &( internal_context->evp_context ),
	     1 ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set padding in context.",
		 function );

		goto on_error;
	}

#else
	if( libcaes_tables_initialized == 0 )
	{
		if( libcaes_initialize_tables(
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to initialize tables.",
			 function );

			goto on_error;
		}
		libcaes_tables_initialized = 1;
	}
#endif
	*context = (libcaes_context_t *) internal_context;

	return( 1 );

on_error:
	if( internal_context != NULL )
	{
		memory_free(
		 internal_context );
	}
	return( -1 );
}

/* Frees a context
 * Returns 1 if successful or -1 on error
 */
int libcaes_context_free(
     libcaes_context_t **context,
     libcerror_error_t **error )
{
	libcaes_internal_context_t *internal_context = NULL;
	static char *function                        = "libcaes_context_free";

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( *context != NULL )
	{
		internal_context = (libcaes_internal_context_t *) *context;
		*context         = NULL;

#if defined( WINAPI ) && ( WINVER >= 0x0600 )
		if( internal_context->key != 0 )
		{
			CryptDestroyKey(
			 internal_context->key );
		}
		if( internal_context->crypt_provider != 0 )
		{
			CryptReleaseContext(
			 internal_context->crypt_provider,
			 0 );
		}

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
		/* No additional clean up necessary */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )
		EVP_CIPHER_CTX_cleanup(
		 &( internal_context->evp_context ) );

		/* Make sure the error state is removed otherwise openssl will leak memory
		 */
		ERR_remove_thread_state(
		 NULL );

#else
		/* No additional clean up necessary */
#endif
		memory_free(
		 internal_context );
	}
	return( 1 );
}

/* Sets the key
 * Returns 1 if successful or -1 on error
 */
int libcaes_context_set_key(
     libcaes_context_t *context,
     int mode,
     const uint8_t *key,
     size_t key_bit_size,
     libcerror_error_t **error )
{
	libcaes_internal_context_t *internal_context = NULL;
	static char *function                        = "libcaes_context_set_key";

#if defined( WINAPI ) && ( WINVER >= 0x0600 )
	libcaes_key_t *wincrypt_key                  = NULL;
	DWORD error_code                             = 0;
	DWORD wincrypt_key_size                      = 0;
#endif

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	internal_context = (libcaes_internal_context_t *) context;

	if( ( mode != LIBCAES_CRYPT_MODE_DECRYPT )
	 && ( mode != LIBCAES_CRYPT_MODE_ENCRYPT ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported mode.",
		 function );

		return( -1 );
	}
	if( ( key_bit_size != 128 )
	 && ( key_bit_size != 192 )
	 && ( key_bit_size != 256 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported key bit size.",
		 function );

		return( -1 );
	}
#if defined( WINAPI ) && ( WINVER >= 0x0600 )
	if( libcaes_key_initialize(
	     &wincrypt_key,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create wincrypt key.",
		 function );

		return( -1 );
	}
	if( libcaes_key_set(
	     wincrypt_key,
	     key,
	     key_bit_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set wincrypt key.",
		 function );

		libcaes_key_free(
		 &wincrypt_key,
		 NULL );

		return( -1 );
	}
	wincrypt_key_size = (DWORD) ( sizeof( libcaes_key_t ) - ( ( 256 - key_bit_size ) / 8 ) );

	if( CryptImportKey(
	     internal_context->crypt_provider,
	     (CONST BYTE *) wincrypt_key,
	     wincrypt_key_size,
	     (HCRYPTKEY) NULL,
	     0,
	     &( internal_context->key ) ) == 0 )
	{
		error_code = GetLastError();

		libcerror_system_set_error(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 error_code,
		 "%s: unable to create key object.",
		 function );

		libcaes_key_free(
		 &wincrypt_key,
		 NULL );

		return( -1 );
	}
	if( libcaes_key_free(
	     &wincrypt_key,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free wincrypt key.",
		 function );

		return( -1 );
	}

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
	if( mode == LIBCAES_CRYPT_MODE_ENCRYPT )
	{
		if( AES_set_encrypt_key(
		     (unsigned char *) key,
		     (int) key_bit_size,
		     &( internal_context->key ) ) != 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to set encryption key.",
			 function );

			return( -1 );
		}
	}
	else
	{
		if( AES_set_decrypt_key(
		     (unsigned char *) key,
		     (int) key_bit_size,
		     &( internal_context->key ) ) != 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to set decryption key.",
			 function );

			return( -1 );
		}
	}

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )
	if( memory_copy(
	     internal_context->key,
	     key,
	     key_bit_size / 8 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy key.",
		 function );

		return( -1 );
	}
	internal_context->key_bit_size = key_bit_size;

#else
	if( mode == LIBCAES_CRYPT_MODE_ENCRYPT )
	{
		if( libcaes_crypt_set_encryption_key(
		     internal_context,
		     key,
		     key_bit_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to set encryption key.",
			 function );

			return( -1 );
		}
	}
	else
	{
		if( libcaes_crypt_set_decryption_key(
		     internal_context,
		     key,
		     key_bit_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to set decryption key.",
			 function );

			return( -1 );
		}
	}
#endif
	return( 1 );
}


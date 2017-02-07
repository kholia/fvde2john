/*
 * AES encryption functions
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

#include "libcaes_context.h"
#include "libcaes_definitions.h"
#include "libcaes_libcerror.h"
#include "libcaes_tweaked_context.h"
#include "libcaes_types.h"

/* Creates a tweaked context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libcaes_tweaked_context_initialize(
     libcaes_tweaked_context_t **context,
     libcerror_error_t **error )
{
	libcaes_internal_tweaked_context_t *internal_context = NULL;
	static char *function                                = "libcaes_tweaked_context_initialize";

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
	                    libcaes_internal_tweaked_context_t );

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
	     sizeof( libcaes_internal_tweaked_context_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear context.",
		 function );

		memory_free(
		 internal_context );

		return( -1 );
	}
	if( libcaes_context_initialize(
	     &( internal_context->main_context ),
	     error ) != 1)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to initialize main context.",
		 function );

		goto on_error;
	}
	if( libcaes_context_initialize(
	     &( internal_context->tweak_context ),
	     error ) != 1)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to initialize tweak context.",
		 function );

		goto on_error;
	}
	*context = (libcaes_tweaked_context_t *) internal_context;

	return( 1 );

on_error:
	if( internal_context != NULL )
	{
		if( internal_context->main_context != NULL )
		{
			libcaes_context_free(
			 &( internal_context->main_context ),
			 NULL );
		}
		memory_free(
		 internal_context );
	}
	return( -1 );
}

/* Frees a tweaked context
 * Returns 1 if successful or -1 on error
 */
int libcaes_tweaked_context_free(
     libcaes_tweaked_context_t **context,
     libcerror_error_t **error )
{
	libcaes_internal_tweaked_context_t *internal_context = NULL;
	static char *function                                = "libcaes_tweaked_context_free";
	int result                                           = 1;

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
		internal_context = (libcaes_internal_tweaked_context_t *) *context;
		*context         = NULL;

		if( libcaes_context_free(
		     &( internal_context->tweak_context ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free tweak context.",
			 function );

			result = -1;
		}
		if( libcaes_context_free(
		     &( internal_context->main_context ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free main context.",
			 function );

			result = -1;
		}
		memory_free(
		 internal_context );
	}
	return( result );
}

/* Sets the keys
 * Returns 1 if successful or -1 on error
 */
int libcaes_tweaked_context_set_keys(
     libcaes_tweaked_context_t *context,
     int mode,
     const uint8_t *key,
     size_t key_bit_size,
     const uint8_t *tweak_key,
     size_t tweak_key_bit_size,
     libcerror_error_t **error )
{
	libcaes_internal_tweaked_context_t *internal_context = NULL;
	static char *function                                = "libcaes_tweaked_context_set_key";

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
	internal_context = (libcaes_internal_tweaked_context_t *) context;

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
	if( libcaes_context_set_key(
	     internal_context->main_context,
	     mode,
	     key,
	     key_bit_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set key in main context.",
		 function );

		return( -1 );
	}
	if( libcaes_context_set_key(
	     internal_context->tweak_context,
	     LIBCAES_CRYPT_MODE_ENCRYPT,
	     tweak_key,
	     tweak_key_bit_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set tweak key in tweak context.",
		 function );

		return( -1 );
	}
	return( 1 );
}


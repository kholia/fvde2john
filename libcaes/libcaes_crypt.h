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

#if !defined( _LIBCAES_CRYPT_H )
#define _LIBCAES_CRYPT_H

#include <common.h>
#include <types.h>

#include "libcaes_context.h"
#include "libcaes_extern.h"
#include "libcaes_libcerror.h"
#include "libcaes_tweaked_context.h"
#include "libcaes_types.h"

#if defined( __cplusplus )
extern "C" {
#endif

#if !defined( LIBCAES_HAVE_AES_SUPPORT )

int libcaes_initialize_tables(
     libcerror_error_t **error );

#endif /* !defined( LIBCAES_HAVE_AES_SUPPORT ) */

#if !defined( LIBCAES_HAVE_AES_SUPPORT )

int libcaes_crypt_set_decryption_key(
     libcaes_internal_context_t *internal_context,
     const uint8_t *key,
     size_t key_bit_size,
     libcerror_error_t **error );

int libcaes_crypt_set_encryption_key(
     libcaes_internal_context_t *internal_context,
     const uint8_t *key,
     size_t key_bit_size,
     libcerror_error_t **error );

#endif /* !defined( LIBCAES_HAVE_AES_SUPPORT ) */

LIBCAES_EXTERN \
int libcaes_crypt_cbc(
     libcaes_context_t *context,
     int mode,
     const uint8_t *initialization_vector,
     size_t initialization_vector_size,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error );

LIBCAES_EXTERN \
int libcaes_crypt_ccm(
     libcaes_context_t *context,
     int mode,
     const uint8_t *nonce,
     size_t nonce_size,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error );

#ifdef TODO
int libcaes_crypt_cfb(
     libcaes_context_t *context,
     int mode,
     const uint8_t *initialization_vector,
     size_t initialization_vector_size,
     size_t *initialization_vector_index,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error );
#endif

LIBCAES_EXTERN \
int libcaes_crypt_ecb(
     libcaes_context_t *context,
     int mode,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error );

LIBCAES_EXTERN \
int libcaes_crypt_xts(
     libcaes_tweaked_context_t *context,
     int mode,
     const uint8_t *tweak_value,
     size_t tweak_value_size,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error );

#ifdef __cplusplus
}
#endif

#endif /* !defined( _LIBCAES_CRYPT_H ) */


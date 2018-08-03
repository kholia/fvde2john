/*
 * Value type functions
 *
 * Copyright (C) 2010-2017, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _LIBFVALUE_INTERNAL_VALUE_TYPE_H )
#define _LIBFVALUE_INTERNAL_VALUE_TYPE_H

#include <common.h>
#include <types.h>

#include <stdio.h>

#include "libfvalue_extern.h"
#include "libfvalue_libcerror.h"
#include "libfvalue_types.h"

#if defined( __cplusplus )
extern "C" {
#endif

LIBFVALUE_EXTERN \
int libfvalue_value_type_initialize(
     libfvalue_value_t **value,
     int type,
     libcerror_error_t **error );

LIBFVALUE_EXTERN \
int libfvalue_value_type_initialize_with_data_handle(
     libfvalue_value_t **value,
     int type,
     libfvalue_data_handle_t *data_handle,
     uint8_t flags,
     libcerror_error_t **error );

ssize_t libfvalue_value_type_get_string_size(
         libfvalue_value_t *value,
         const uint8_t *data,
         size_t data_size,
         libcerror_error_t **error );

LIBFVALUE_EXTERN \
ssize_t libfvalue_value_type_set_data_string(
         libfvalue_value_t *value,
         const uint8_t *data,
         size_t data_size,
         int encoding,
         uint8_t flags,
         libcerror_error_t **error );

LIBFVALUE_EXTERN \
ssize_t libfvalue_value_type_append_data_string(
         libfvalue_value_t *value,
         const uint8_t *data,
         size_t data_size,
         int encoding,
         libcerror_error_t **error );

LIBFVALUE_EXTERN \
ssize_t libfvalue_value_type_set_data_strings_array(
         libfvalue_value_t *value,
         const uint8_t *data,
         size_t data_size,
         int encoding,
         libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFVALUE_INTERNAL_VALUE_TYPE_H ) */


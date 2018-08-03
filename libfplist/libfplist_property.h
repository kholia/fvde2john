/*
 * Property functions
 *
 * Copyright (C) 2016-2018, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _LIBFPLIST_PROPERTY_H )
#define _LIBFPLIST_PROPERTY_H

#include <common.h>
#include <types.h>

#include "libfplist_extern.h"
#include "libfplist_libcerror.h"
#include "libfplist_types.h"
#include "libfplist_xml_tag.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libfplist_internal_property libfplist_internal_property_t;

struct libfplist_internal_property
{
	/* The key XML tag
	 */
	libfplist_xml_tag_t *key_tag;

	/* The value XML tag
	 */
	libfplist_xml_tag_t *value_tag;

	/* The value type
	 */
	int value_type;
};

int libfplist_property_initialize(
     libfplist_property_t **property,
     libfplist_xml_tag_t *key_tag,
     libfplist_xml_tag_t *value_tag,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_free(
     libfplist_property_t **property,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_get_value_type(
     libfplist_property_t *property,
     int *value_type,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_get_value_data_size(
     libfplist_property_t *property,
     size_t *data_size,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_get_value_data(
     libfplist_property_t *property,
     uint8_t *data,
     size_t data_size,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_get_value_integer(
     libfplist_property_t *property,
     uint64_t *value_64bit,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_get_value_string(
     libfplist_property_t *property,
     uint8_t **string,
     size_t *string_size,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_value_uuid_string_copy_to_byte_stream(
     libfplist_property_t *property,
     uint8_t *byte_stream,
     size_t byte_stream_size,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_get_array_number_of_entries(
     libfplist_property_t *property,
     int *number_of_entries,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_get_array_entry_by_index(
     libfplist_property_t *property,
     int array_entry_index,
     libfplist_property_t **array_entry,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_get_sub_property_by_utf8_name(
     libfplist_property_t *property,
     const uint8_t *utf8_string,
     size_t utf8_string_length,
     libfplist_property_t **sub_property,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFPLIST_PROPERTY_H ) */


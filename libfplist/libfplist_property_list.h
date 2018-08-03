/*
 * Property list functions
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

#if !defined( _LIBFPLIST_PROPERTY_LIST_H )
#define _LIBFPLIST_PROPERTY_LIST_H

#include <common.h>
#include <types.h>

#include "libfplist_extern.h"
#include "libfplist_libcerror.h"
#include "libfplist_types.h"
#include "libfplist_xml_tag.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libfplist_internal_property_list libfplist_internal_property_list_t;

struct libfplist_internal_property_list
{
	/* The plist XML tag
	 */
	libfplist_xml_tag_t *plist_tag;

	/* The root XML tag
	 */
	libfplist_xml_tag_t *root_tag;

	/* The (main) dict XML tag
	 */
	libfplist_xml_tag_t *dict_tag;
};

LIBFPLIST_EXTERN \
int libfplist_property_list_initialize(
     libfplist_property_list_t **property_list,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_list_free(
     libfplist_property_list_t **property_list,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_list_copy_from_byte_stream(
     libfplist_property_list_t *property_list,
     const uint8_t *byte_stream,
     size_t byte_stream_size,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_list_has_plist_root_element(
     libfplist_property_list_t *property_list,
     libcerror_error_t **error );

LIBFPLIST_EXTERN \
int libfplist_property_list_get_root_property(
     libfplist_property_list_t *property_list,
     libfplist_property_t **property,
     libcerror_error_t **error );

int libfplist_property_list_set_root_tag(
     libfplist_property_list_t *property_list,
     libfplist_xml_tag_t *tag,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFPLIST_PROPERTY_LIST_H ) */


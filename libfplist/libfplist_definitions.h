/*
 * The internal definitions
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

#if !defined( LIBFPLIST_INTERNAL_DEFINITIONS_H )
#define LIBFPLIST_INTERNAL_DEFINITIONS_H

#include <common.h>
#include <types.h>

/* Define HAVE_LOCAL_LIBFPLIST for local use of libfplist
 */
#if !defined( HAVE_LOCAL_LIBFPLIST )
#include <libfplist/definitions.h>

/* The definitions in <libfplist/definitions.h> are copied here
 * for local use of libfplist
 */
#else
#include <byte_stream.h>

#define LIBFPLIST_VERSION			20180108

/* The version string
 */
#define LIBFPLIST_VERSION_STRING		"20180108"

enum LIBFPLIST_VALUE_TYPES
{
	LIBFPLIST_VALUE_TYPE_UNKNOWN		= 0,
	LIBFPLIST_VALUE_TYPE_ARRAY		= 1,
	LIBFPLIST_VALUE_TYPE_BINARY_DATA	= 2,
	LIBFPLIST_VALUE_TYPE_BOOLEAN		= 3,
	LIBFPLIST_VALUE_TYPE_DATE		= 4,
	LIBFPLIST_VALUE_TYPE_DICTIONARY		= 5,
	LIBFPLIST_VALUE_TYPE_FLOATING_POINT	= 6,
	LIBFPLIST_VALUE_TYPE_INTEGER		= 7,
	LIBFPLIST_VALUE_TYPE_STRING		= 8
};

#endif /* !defined( HAVE_LOCAL_LIBFPLIST ) */

#endif /* !defined( LIBFPLIST_INTERNAL_DEFINITIONS_H ) */


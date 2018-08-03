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

#include <common.h>
#include <memory.h>
#include <narrow_string.h>
#include <types.h>

#include "libfplist_definitions.h"
#include "libfplist_libcerror.h"
#include "libfplist_libcnotify.h"
#include "libfplist_libfguid.h"
#include "libfplist_libfvalue.h"
#include "libfplist_libuna.h"
#include "libfplist_property.h"
#include "libfplist_types.h"
#include "libfplist_xml_tag.h"

/* Creates a property
 * Make sure the value property is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_initialize(
     libfplist_property_t **property,
     libfplist_xml_tag_t *key_tag,
     libfplist_xml_tag_t *value_tag,
     libcerror_error_t **error )
{
	libfplist_internal_property_t *internal_property = NULL;
	static char *function                            = "libfplist_property_initialize";
	int result                                       = 0;

	if( property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property.",
		 function );

		return( -1 );
	}
	if( *property != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid property value already set.",
		 function );

		return( -1 );
	}
	if( value_tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid value XML tag.",
		 function );

		return( -1 );
	}
	if( key_tag != NULL )
	{
		result = libfplist_xml_tag_compare_name(
		          key_tag,
		          (uint8_t *) "key",
		          3,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to compare name of key tag.",
			 function );

			return( -1 );
		}
		else if( result == 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: unsupported key tag: %s.",
			 function,
			 key_tag->name );

			return( -1 );
		}
	}
	internal_property = memory_allocate_structure(
	                     libfplist_internal_property_t );

	if( internal_property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create property.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     internal_property,
	     0,
	     sizeof( libfplist_internal_property_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear property.",
		 function );
	
		memory_free(
		 internal_property );

		return( -1 );
	}
	internal_property->key_tag   = key_tag;
	internal_property->value_tag = value_tag;

	*property = (libfplist_property_t *) internal_property;

	return( 1 );

on_error:
	if( internal_property != NULL )
	{
		memory_free(
		 internal_property );
	}
	return( -1 );
}

/* Frees a property
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_free(
    libfplist_property_t **property,
    libcerror_error_t **error )
{
	libfplist_internal_property_t *internal_property = NULL;
	static char *function                            = "libfplist_property_free";

	if( property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property.",
		 function );

		return( -1 );
	}
	if( *property != NULL )
	{
		internal_property = (libfplist_internal_property_t *) *property;
		*property         = NULL;

		/* The key_tag and value_tag are referenced and freed elsewhere */

		memory_free(
		 internal_property );
	}
	return( 1 );
}

/* Retrieves the value type
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_get_value_type(
     libfplist_property_t *property,
     int *value_type,
     libcerror_error_t **error )
{
	libfplist_internal_property_t *internal_property = NULL;
	static char *function                            = "libfplist_property_get_value_type";

	if( property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property.",
		 function );

		return( -1 );
	}
	internal_property = (libfplist_internal_property_t *) property;

	if( internal_property->value_tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid property - missing value XML tag.",
		 function );

		return( -1 );
	}
	if( value_type == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid value type.",
		 function );

		return( -1 );
	}
	if( internal_property->value_type == LIBFPLIST_VALUE_TYPE_UNKNOWN )
	{
		if( libfplist_xml_tag_get_value_type(
		     internal_property->value_tag,
		     &( internal_property->value_type ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve value type.",
			 function );

			return( -1 );
		}
	}
	if( internal_property->value_type == LIBFPLIST_VALUE_TYPE_UNKNOWN )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported value type.",
		 function );

		return( -1 );
	}
	*value_type = internal_property->value_type;

	return( 1 );
}

/* Retrieves the value (binary) data size
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_get_value_data_size(
     libfplist_property_t *property,
     size_t *data_size,
     libcerror_error_t **error )
{
	libfplist_internal_property_t *internal_property = NULL;
	static char *function                            = "libfplist_property_get_value_data_size";
	size_t value_index                     = 0;
	size_t value_length                    = 0;

	if( property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property.",
		 function );

		return( -1 );
	}
	internal_property = (libfplist_internal_property_t *) property;

	if( internal_property->value_tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid property - missing value XML tag.",
		 function );

		return( -1 );
	}
	if( data_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid data size.",
		 function );

		return( -1 );
	}
	if( internal_property->value_type == LIBFPLIST_VALUE_TYPE_UNKNOWN )
	{
		if( libfplist_xml_tag_get_value_type(
		     internal_property->value_tag,
		     &( internal_property->value_type ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve value type.",
			 function );

			return( -1 );
		}
	}
	if( internal_property->value_type != LIBFPLIST_VALUE_TYPE_BINARY_DATA )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported value type.",
		 function );

		return( -1 );
	}
	value_length = internal_property->value_tag->value_size - 1;

	/* The base64 conversion function doesn't like an empty first line
	 */
	if( ( internal_property->value_tag->value )[ 0 ] == '\n' )
	{
		value_index  += 1;
		value_length -= 1;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: base64 encoded data:\n",
		 function );
		libcnotify_print_data(
		 (uint8_t *) &( ( internal_property->value_tag->value )[ value_index ] ),
		 value_length,
		 0 );
	}
#endif
	if( libuna_base64_stream_size_to_byte_stream(
	     &( ( internal_property->value_tag->value )[ value_index ] ),
	     value_length,
	     data_size,
	     LIBUNA_BASE64_VARIANT_ALPHABET_NORMAL | LIBUNA_BASE64_VARIANT_CHARACTER_LIMIT_NONE | LIBUNA_BASE64_VARIANT_PADDING_REQUIRED,
	     LIBUNA_BASE64_FLAG_STRIP_WHITESPACE,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_COPY_FAILED,
		 "%s: unable to determine size of base64 encoded data.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Copies the value (binary) data
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_get_value_data(
     libfplist_property_t *property,
     uint8_t *data,
     size_t data_size,
     libcerror_error_t **error )
{
	libfplist_internal_property_t *internal_property = NULL;
	static char *function                            = "libfplist_property_get_value_data";
	size_t value_index                               = 0;
	size_t value_length                              = 0;

	if( property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property.",
		 function );

		return( -1 );
	}
	internal_property = (libfplist_internal_property_t *) property;

	if( internal_property->value_tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid property - missing value XML tag.",
		 function );

		return( -1 );
	}
	if( data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid data.",
		 function );

		return( -1 );
	}
	if( data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( internal_property->value_type == LIBFPLIST_VALUE_TYPE_UNKNOWN )
	{
		if( libfplist_xml_tag_get_value_type(
		     internal_property->value_tag,
		     &( internal_property->value_type ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve value type.",
			 function );

			return( -1 );
		}
	}
	if( internal_property->value_type != LIBFPLIST_VALUE_TYPE_BINARY_DATA )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported value type.",
		 function );

		return( -1 );
	}
	value_length = internal_property->value_tag->value_size - 1;

	/* The base64 conversion function doesn't like an empty first line
	 */
	if( ( internal_property->value_tag->value )[ 0 ] == '\n' )
	{
		value_index  += 1;
		value_length -= 1;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: base64 encoded data:\n",
		 function );
		libcnotify_print_data(
		 (uint8_t *) &( ( internal_property->value_tag->value )[ value_index ] ),
		 value_length,
		 0 );
	}
#endif
	if( libuna_base64_stream_copy_to_byte_stream(
	     &( ( internal_property->value_tag->value )[ value_index ] ),
	     value_length,
	     data,
	     data_size,
	     LIBUNA_BASE64_VARIANT_ALPHABET_NORMAL | LIBUNA_BASE64_VARIANT_CHARACTER_LIMIT_NONE | LIBUNA_BASE64_VARIANT_PADDING_REQUIRED,
	     LIBUNA_BASE64_FLAG_STRIP_WHITESPACE,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_COPY_FAILED,
		 "%s: unable to copy base64 encoded data to byte stream.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves an integer value
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_get_value_integer(
     libfplist_property_t *property,
     uint64_t *value_64bit,
     libcerror_error_t **error )
{
	libfplist_internal_property_t *internal_property = NULL;
	static char *function                            = "libfplist_property_get_value_integer";

	if( property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property.",
		 function );

		return( -1 );
	}
	internal_property = (libfplist_internal_property_t *) property;

	if( internal_property->value_tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid property - missing value XML tag.",
		 function );

		return( -1 );
	}
	if( internal_property->value_type == LIBFPLIST_VALUE_TYPE_UNKNOWN )
	{
		if( libfplist_xml_tag_get_value_type(
		     internal_property->value_tag,
		     &( internal_property->value_type ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve value type.",
			 function );

			return( -1 );
		}
	}
	if( internal_property->value_type != LIBFPLIST_VALUE_TYPE_INTEGER )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported value type.",
		 function );

		return( -1 );
	}
/* TODO add size support ? */
	if( libfvalue_utf8_string_copy_to_integer(
	     internal_property->value_tag->value,
	     internal_property->value_tag->value_size - 1,
	     (uint64_t *) value_64bit,
	     64,
	     LIBFVALUE_INTEGER_FORMAT_TYPE_DECIMAL | LIBFVALUE_INTEGER_FORMAT_FLAG_UNSIGNED,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_COPY_FAILED,
		 "%s: unable to convert value to integer.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves a string value
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_get_value_string(
     libfplist_property_t *property,
     uint8_t **string,
     size_t *string_size,
     libcerror_error_t **error )
{
	libfplist_internal_property_t *internal_property = NULL;
	static char *function                            = "libfplist_property_get_value_string";

	if( property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property.",
		 function );

		return( -1 );
	}
	internal_property = (libfplist_internal_property_t *) property;

	if( internal_property->value_tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid property - missing value XML tag.",
		 function );

		return( -1 );
	}
	if( string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid string.",
		 function );

		return( -1 );
	}
	if( *string != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid string value already set.",
		 function );

		return( -1 );
	}
	if( string_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid string size.",
		 function );

		return( -1 );
	}
	if( internal_property->value_type == LIBFPLIST_VALUE_TYPE_UNKNOWN )
	{
		if( libfplist_xml_tag_get_value_type(
		     internal_property->value_tag,
		     &( internal_property->value_type ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve value type.",
			 function );

			return( -1 );
		}
	}
	if( internal_property->value_type != LIBFPLIST_VALUE_TYPE_STRING )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported value type.",
		 function );

		return( -1 );
	}
	*string_size = internal_property->value_tag->value_size;

	*string = memory_allocate(
	           sizeof( uint8_t ) * internal_property->value_tag->value_size );

	if( *string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create string.",
		 function );

		goto on_error;
	}
	if( memory_copy(
	     *string,
	     internal_property->value_tag->value,
	     internal_property->value_tag->value_size ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy string.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( *string != NULL )
	{
		memory_free(
		 *string );

		*string = NULL;
	}
	*string_size = 0;

	return( -1 );
}

/* Copies an UUID string value to a byte stream
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_value_uuid_string_copy_to_byte_stream(
     libfplist_property_t *property,
     uint8_t *byte_stream,
     size_t byte_stream_size,
     libcerror_error_t **error )
{
	libfguid_identifier_t *guid = NULL;
	uint8_t *string             = NULL;
	static char *function       = "libfplist_property_value_uuid_string_copy_to_byte_stream";
	size_t string_size          = 0;
	int result                  = 0;

	if( libfplist_property_get_value_string(
	     property,
	     &string,
	     &string_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve logical volume family identifier.",
		 function );

		goto on_error;
	}
	if( string_size == 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid string size value out of bounds.",
		 function );

		return( -1 );
	}
	if( libfguid_identifier_initialize(
	     &guid,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create GUID.",
		 function );

		goto on_error;
	}
	result = libfguid_identifier_copy_from_utf8_string(
		  guid,
		  (uint8_t *) string,
		  string_size - 1,
		  LIBFGUID_STRING_FORMAT_FLAG_USE_MIXED_CASE,
		  error );

	if( result != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to copy GUID from string.",
		 function );

		goto on_error;
	}
	memory_free(
	 string );

	string = NULL;

	if( libfguid_identifier_copy_to_byte_stream(
	     guid,
	     byte_stream,
	     byte_stream_size,
	     LIBFGUID_ENDIAN_BIG,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to copy GUID to byte stream.",
		 function );

		goto on_error;
	}
	if( libfguid_identifier_free(
	     &guid,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free GUID.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
#if defined( HAVE_DEBUG_OUTPUT )
	if( string != NULL )
	{
		memory_free(
		 string );
	}
#endif
	if( guid != NULL )
	{
		libfguid_identifier_free(
		 &guid,
		 NULL );
	}
	return( -1 );
}

/* Retrieves the number of array entries
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_get_array_number_of_entries(
     libfplist_property_t *property,
     int *number_of_entries,
     libcerror_error_t **error )
{
	libfplist_internal_property_t *internal_property = NULL;
	libfplist_xml_tag_t *element_tag                 = NULL;
	static char *function                            = "libfplist_property_get_array_number_of_entries";
	int element_index                                = 0;
	int number_of_elements                           = 0;
	int number_of_nodes                              = 0;
	int result                                       = 0;

	if( property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property.",
		 function );

		return( -1 );
	}
	internal_property = (libfplist_internal_property_t *) property;

	if( internal_property->value_tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid property - missing value XML tag.",
		 function );

		return( -1 );
	}
	if( number_of_entries == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid number of entries.",
		 function );

		return( -1 );
	}
	if( internal_property->value_type == LIBFPLIST_VALUE_TYPE_UNKNOWN )
	{
		if( libfplist_xml_tag_get_value_type(
		     internal_property->value_tag,
		     &( internal_property->value_type ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve value type.",
			 function );

			return( -1 );
		}
	}
	if( internal_property->value_type != LIBFPLIST_VALUE_TYPE_ARRAY )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported value type.",
		 function );

		return( -1 );
	}
	if( libfplist_xml_tag_get_number_of_elements(
	     internal_property->value_tag,
	     &number_of_elements,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of elements.",
		 function );

		return( -1 );
	}
	for( element_index = 0;
	     element_index < number_of_elements;
	     element_index++ )
	{
		if( libfplist_xml_tag_get_element(
		     internal_property->value_tag,
		     element_index,
		     &element_tag,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve element: %d.",
			 function,
			 element_index );

			return( -1 );
		}
		/* Ignore text nodes
		 */
		result = libfplist_xml_tag_compare_name(
		          element_tag,
		          (uint8_t *) "text",
		          4,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to compare name of value tag.",
			 function );

			return( -1 );
		}
		else if( result == 0 )
		{
			number_of_nodes++;
		}
	}
	*number_of_entries = number_of_nodes;

	return( 1 );
}

/* Retrieves a specific array entry
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_get_array_entry_by_index(
     libfplist_property_t *property,
     int array_entry_index,
     libfplist_property_t **array_entry,
     libcerror_error_t **error )
{
	libfplist_internal_property_t *internal_property = NULL;
	libfplist_xml_tag_t *value_tag                   = NULL;
	static char *function                            = "libfplist_property_get_array_entry_by_index";
	int entry_index                                  = 0;
	int element_index                                = 0;
	int number_of_elements                           = 0;
	int result                                       = 0;

	if( property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property.",
		 function );

		return( -1 );
	}
	internal_property = (libfplist_internal_property_t *) property;

	if( internal_property->value_tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid property - missing value XML tag.",
		 function );

		return( -1 );
	}
	if( array_entry_index < 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid array entry index value out of bounds.",
		 function );

		return( -1 );
	}
	if( array_entry == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid array entry.",
		 function );

		return( -1 );
	}
	if( *array_entry != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid array entry value already set.",
		 function );

		return( -1 );
	}
	if( internal_property->value_type == LIBFPLIST_VALUE_TYPE_UNKNOWN )
	{
		if( libfplist_xml_tag_get_value_type(
		     internal_property->value_tag,
		     &( internal_property->value_type ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve value type.",
			 function );

			return( -1 );
		}
	}
	if( internal_property->value_type != LIBFPLIST_VALUE_TYPE_ARRAY )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported value type.",
		 function );

		return( -1 );
	}
	if( libfplist_xml_tag_get_number_of_elements(
	     internal_property->value_tag,
	     &number_of_elements,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of elements.",
		 function );

		return( -1 );
	}
	entry_index = array_entry_index;

	element_index = 0;

	while( element_index < number_of_elements )
	{
		if( libfplist_xml_tag_get_element(
		     internal_property->value_tag,
		     element_index,
		     &value_tag,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve element: %d.",
			 function,
			 element_index );

			return( -1 );
		}
		/* Ignore text nodes
		 */
		result = libfplist_xml_tag_compare_name(
		          value_tag,
		          (uint8_t *) "text",
		          4,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to compare name of value tag.",
			 function );

			return( -1 );
		}
		else if( result == 0 )
		{
			if( entry_index == 0 )
			{
				break;
			}
			entry_index--;
		}
		element_index++;
	}
	if( element_index >= number_of_elements )
	{
		return( 0 );
	}
	if( libfplist_property_initialize(
	     array_entry,
	     NULL,
	     value_tag,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create array entry: %d.",
		 function,
		 array_entry_index );

		return( -1 );
	}
	return( 1 );
}

/* Retrieves the sub property for the specific UTF-8 encoded name
 * Returns 1 if successful, 0 if no such sub property or -1 on error
 */
int libfplist_property_get_sub_property_by_utf8_name(
     libfplist_property_t *property,
     const uint8_t *utf8_string,
     size_t utf8_string_length,
     libfplist_property_t **sub_property,
     libcerror_error_t **error )
{
	libfplist_internal_property_t *internal_property = NULL;
	libfplist_xml_tag_t *key_tag                     = NULL;
	libfplist_xml_tag_t *value_tag                   = NULL;
	static char *function                            = "libfplist_property_get_sub_property_by_utf8_name";
	int element_index                                = 0;
	int number_of_elements                           = 0;
	int result                                       = 0;

	if( property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property.",
		 function );

		return( -1 );
	}
	internal_property = (libfplist_internal_property_t *) property;

	if( internal_property->value_tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid property - missing value XML tag.",
		 function );

		return( -1 );
	}
	if( utf8_string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid UTF-8 string.",
		 function );

		return( -1 );
	}
	if( utf8_string_length > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid UTF-8 string length value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( sub_property == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid sub property.",
		 function );

		return( -1 );
	}
	if( *sub_property != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid sub property value already set.",
		 function );

		return( -1 );
	}
	if( internal_property->value_type == LIBFPLIST_VALUE_TYPE_UNKNOWN )
	{
		if( libfplist_xml_tag_get_value_type(
		     internal_property->value_tag,
		     &( internal_property->value_type ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve value type.",
			 function );

			return( -1 );
		}
	}
	if( internal_property->value_type != LIBFPLIST_VALUE_TYPE_DICTIONARY )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported value type.",
		 function );

		return( -1 );
	}
	if( libfplist_xml_tag_get_number_of_elements(
	     internal_property->value_tag,
	     &number_of_elements,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve number of elements.",
		 function );

		return( -1 );
	}
	element_index = 0;

	while( element_index < number_of_elements )
	{
		if( libfplist_xml_tag_get_element(
		     internal_property->value_tag,
		     element_index,
		     &key_tag,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve element: %d.",
			 function,
			 element_index );

			return( -1 );
		}
		result = libfplist_xml_tag_compare_name(
		          key_tag,
		          (uint8_t *) "key",
		          3,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to compare name of key tag.",
			 function );

			return( -1 );
		}
		else if( result != 0 )
		{
			if( ( key_tag->value_size == ( utf8_string_length + 1 ) )
			 && narrow_string_compare(
			     key_tag->value,
			     utf8_string,
			     utf8_string_length ) == 0 )
			{
				break;
			}
		}
		element_index++;
	}
	if( element_index >= number_of_elements )
	{
		return( 0 );
	}
	element_index++;

	while( element_index < number_of_elements )
	{
		if( libfplist_xml_tag_get_element(
		     internal_property->value_tag,
		     element_index,
		     &value_tag,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve element: %d.",
			 function,
			 element_index );

			return( -1 );
		}
		/* Ignore text nodes
		 */
		result = libfplist_xml_tag_compare_name(
		          value_tag,
		          (uint8_t *) "text",
		          4,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to compare name of value tag.",
			 function );

			return( -1 );
		}
		else if( result == 0 )
		{
			break;
		}
		element_index++;
	}
	if( element_index >= number_of_elements )
	{
		return( 0 );
	}
	if( libfplist_property_initialize(
	     sub_property,
	     key_tag,
	     value_tag,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create sub property.",
		 function );

		return( -1 );
	}
	return( 1 );
}


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

#include <common.h>
#include <memory.h>
#include <types.h>

#include "libfplist_libcerror.h"
#include "libfplist_libcnotify.h"
#include "libfplist_property.h"
#include "libfplist_property_list.h"
#include "libfplist_types.h"
#include "libfplist_xml_parser.h"

extern \
int xml_parser_parse_buffer(
     libfplist_property_list_t *property_list,
     const uint8_t *buffer,
     size_t buffer_size,
     libcerror_error_t **error );

/* Creates a property list
 * Make sure the value property_list is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_list_initialize(
    libfplist_property_list_t **property_list,
    libcerror_error_t **error )
{
	libfplist_internal_property_list_t *internal_property_list = NULL;
	static char *function                                      = "libfplist_property_list_initialize";

	if( property_list == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property list.",
		 function );

		return( -1 );
	}
	if( *property_list != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid property list value already set.",
		 function );

		return( -1 );
	}
	internal_property_list = memory_allocate_structure(
	                          libfplist_internal_property_list_t );

	if( internal_property_list == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create property list.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     internal_property_list,
	     0,
	     sizeof( libfplist_internal_property_list_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear property list.",
		 function );
	
		memory_free(
		 internal_property_list );

		return( -1 );
	}
	*property_list = (libfplist_property_list_t *) internal_property_list;

	return( 1 );

on_error:
	if( internal_property_list != NULL )
	{
		memory_free(
		 internal_property_list );
	}
	return( -1 );
}

/* Frees a property list
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_list_free(
    libfplist_property_list_t **property_list,
    libcerror_error_t **error )
{
	libfplist_internal_property_list_t *internal_property_list = NULL;
	static char *function                                      = "libfplist_property_list_free";
	int result                                                 = 1;

	if( property_list == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property list.",
		 function );

		return( -1 );
	}
	if( *property_list != NULL )
	{
		internal_property_list = (libfplist_internal_property_list_t *) *property_list;
		*property_list         = NULL;

		/* The root_tag and dict_tag are referenced and freed elsewhere */

		if( libfplist_xml_tag_free(
		     &( internal_property_list->root_tag ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free root XML tag.",
			 function );

			result = -1;
		}
		memory_free(
		 internal_property_list );
	}
	return( result );
}

/* Copies the property list from the byte stream
 * Returns 1 if successful, 0 if not a valid property list or -1 on error
 */
int libfplist_property_list_copy_from_byte_stream(
     libfplist_property_list_t *property_list,
     const uint8_t *byte_stream,
     size_t byte_stream_size,
     libcerror_error_t **error )
{
	libfplist_internal_property_list_t *internal_property_list = NULL;
	libfplist_xml_tag_t *element_tag                           = NULL;
	uint8_t *buffer                                            = NULL;
	static char *function                                      = "libfplist_property_list_copy_from_byte_stream";
	size_t buffer_size                                         = 0;
	int element_index                                          = 0;
	int number_of_elements                                     = 0;
	int result                                                 = 0;

	if( property_list == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property list.",
		 function );

		return( -1 );
	}
	internal_property_list = (libfplist_internal_property_list_t *) property_list;

	if( internal_property_list->dict_tag != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid property list - dict XML tag already set.",
		 function );

		return( -1 );
	}
	if( internal_property_list->root_tag != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid property list - root XML tag already set.",
		 function );

		return( -1 );
	}
	if( byte_stream == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte stream.",
		 function );

		return( -1 );
	}
	if( ( byte_stream_size < 2 )
	 || ( byte_stream_size > (size_t) INT_MAX )
	 || ( byte_stream_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid byte stream size value out of bounds.",
		 function );

		return( -1 );
	}
	/* Lex wants 2 zero bytes at the end of the buffer
	 */
	if( ( byte_stream[ byte_stream_size - 2 ] == 0 )
	 && ( byte_stream[ byte_stream_size - 1 ] == 0 ) )
	{
		buffer      = (uint8_t *) byte_stream;
		buffer_size = byte_stream_size;
	}
	else
	{
		if( byte_stream[ byte_stream_size - 1 ] == 0 )
		{
			buffer_size = byte_stream_size + 1;
		}
		else
		{
			buffer_size = byte_stream_size + 2;
		}
		buffer = (uint8_t *) memory_allocate(
		                      sizeof( uint8_t ) * buffer_size );

		if( buffer == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create buffer.",
			 function );

			goto on_error;
		}
		if( memory_copy(
		     buffer,
		     byte_stream,
		     byte_stream_size ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
			 "%s: unable to copy byte stream.",
			 function );
	
			goto on_error;
		}
		buffer[ buffer_size - 2 ] = 0;
		buffer[ buffer_size - 1 ] = 0;
	}
	result = xml_parser_parse_buffer(
	          property_list,
	          buffer,
	          buffer_size,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to parse XML.",
		 function );

		goto on_error;
	}
	if( buffer != byte_stream )
	{
		memory_free(
		 buffer );

		buffer = NULL;
	}
	if( internal_property_list->root_tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid property list - missing root XML tag.",
		 function );

		goto on_error;
	}
	result = libfplist_xml_tag_compare_name(
	          internal_property_list->root_tag,
	          (uint8_t *) "dict",
	          4,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to compare name of root tag.",
		 function );

		goto on_error;
	}
	else if( result == 1 )
	{
		internal_property_list->dict_tag = internal_property_list->root_tag;
	}
	else
	{
		/* Ignore the plist XML node
		 * <plist version="1.0">
		 */
		result = libfplist_xml_tag_compare_name(
		          internal_property_list->root_tag,
		          (uint8_t *) "plist",
		          5,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to compare name of root tag.",
			 function );

			goto on_error;
		}
		else if( result == 1 )
		{
			internal_property_list->plist_tag = internal_property_list->root_tag;

			if( libfplist_xml_tag_get_number_of_elements(
			     internal_property_list->root_tag,
			     &number_of_elements,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve number of elements.",
				 function );

				goto on_error;
			}
			for( element_index = 0;
			     element_index < number_of_elements;
			     element_index++ )
			{
				if( libfplist_xml_tag_get_element(
				     internal_property_list->root_tag,
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

					goto on_error;
				}
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
					 "%s: unable to compare name of element tag: %d.",
					 function,
					 element_index );

					goto on_error;
				}
				else if( result != 0 )
				{
					/* Ignore text nodes
					 */
					continue;
				}
				result = libfplist_xml_tag_compare_name(
				          element_tag,
				          (uint8_t *) "dict",
				          4,
				          error );

				if( result == -1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
					 "%s: unable to compare name of element tag: %d.",
					 function,
					 element_index );

					goto on_error;
				}
				else if( result != 0 )
				{
					internal_property_list->dict_tag = element_tag;
				}
				else
				{
					break;
				}
			}
		}
	}
	return( 1 );

on_error:
	if( ( buffer != NULL )
	 && ( buffer != byte_stream ) )
	{
		memory_free(
		 buffer );
	}
	return( -1 );
}

/* Determines if the property list is XML with a plist root element
 * Returns 1 if true, 0 if not or -1 on error
 */
int libfplist_property_list_has_plist_root_element(
     libfplist_property_list_t *property_list,
     libcerror_error_t **error )
{
	libfplist_internal_property_list_t *internal_property_list = NULL;
	static char *function                                      = "libfplist_property_list_has_plist_root_element";

	if( property_list == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property list.",
		 function );

		return( -1 );
	}
	internal_property_list = (libfplist_internal_property_list_t *) property_list;

	if( internal_property_list->plist_tag == NULL )
	{
		return( 0 );
	}
	return( 1 );
}

/* Retrieves the root property
 * Returns 1 if successful, 0 if not available or -1 on error
 */
int libfplist_property_list_get_root_property(
     libfplist_property_list_t *property_list,
     libfplist_property_t **property,
     libcerror_error_t **error )
{
	libfplist_internal_property_list_t *internal_property_list = NULL;
	static char *function                                      = "libfplist_property_list_get_root_property";

	if( property_list == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property list.",
		 function );

		return( -1 );
	}
	internal_property_list = (libfplist_internal_property_list_t *) property_list;

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
	if( internal_property_list->dict_tag == NULL )
	{
		return( 0 );
	}
	if( libfplist_property_initialize(
	     property,
	     NULL,
	     internal_property_list->dict_tag,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create property.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Sets the root tag
 * Returns 1 if successful or -1 on error
 */
int libfplist_property_list_set_root_tag(
     libfplist_property_list_t *property_list,
     libfplist_xml_tag_t *tag,
     libcerror_error_t **error )
{
	libfplist_internal_property_list_t *internal_property_list = NULL;
	static char *function                                      = "libfplist_property_list_set_root_tag";

	if( property_list == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid property list.",
		 function );

		return( -1 );
	}
	internal_property_list = (libfplist_internal_property_list_t *) property_list;

	if( tag == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid tag.",
		 function );

		return( -1 );
	}
	internal_property_list->root_tag = tag;

	return( 1 );
}


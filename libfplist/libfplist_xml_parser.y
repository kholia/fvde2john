%{
/*
 * XML parser functions
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

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "libfplist_libcerror.h"
#include "libfplist_libcnotify.h"
#include "libfplist_property_list.h"
#include "libfplist_types.h"
#include "libfplist_xml_tag.h"

#define YYMALLOC	xml_scanner_alloc
#define YYREALLOC	xml_scanner_realloc
#define YYFREE		xml_scanner_free

#define YYLEX_PARAM	NULL
#define YYPARSE_PARAM	parser_state

#if defined( HAVE_DEBUG_OUTPUT )
#define xml_parser_rule_print( string ) \
	if( libcnotify_verbose != 0 ) libcnotify_printf( "xml_parser: rule: %s\n", string )
#else
#define xml_parser_rule_print( string )
#endif

%}

/* %name-prefix="xml_scanner_" replaced by -p xml_scanner_ */
/* %no-lines replaced by -l */

%lex-param { (void *) NULL }
%parse-param { void *parser_state }

%start xml_plist_main

%union
{
        /* The numeric value
         */
        uint32_t numeric_value;

        /* The string value
         */
	struct xml_plist_string_value
	{
		/* The string data
		 */
	        const char *data;

		/* The string length
		 */
		size_t length;

	} string_value;
}

%{

typedef struct xml_parser_state xml_parser_state_t;

struct xml_parser_state
{
	/* The property list
	 */
	libfplist_property_list_t *property_list;

	/* The error
	 */
	libcerror_error_t **error;

	/* The root XML tag
	 */
	libfplist_xml_tag_t *root_tag;

	/* The current XML tag
	 */
	libfplist_xml_tag_t *current_tag;

	/* The parent XML tag
	 */
	libfplist_xml_tag_t *parent_tag;
};

typedef size_t yy_size_t;
typedef struct yy_buffer_state* YY_BUFFER_STATE;

extern int xml_scanner_suppress_error;

extern int xml_scanner_lex_destroy(
            void );

extern void *xml_scanner_alloc(
              yy_size_t size );

extern void *xml_scanner_realloc(
              void *buffer,
              yy_size_t size );

extern void *xml_scanner_free(
              void *buffer );

extern int xml_scanner_lex(
            void *user_data );

extern void xml_scanner_error(
             void *parser_state,
             const char *error_string );

extern YY_BUFFER_STATE xml_scanner__scan_buffer(
                        char *buffer,
                        yy_size_t buffer_size );

extern void xml_scanner__delete_buffer(
             YY_BUFFER_STATE buffer_state );

extern size_t xml_scanner_buffer_offset;

static char *xml_parser_function = "xml_parser";

int xml_parser_parse_buffer(
     libfplist_property_list_t *property_list,
     const uint8_t *buffer,
     size_t buffer_size,
     libcerror_error_t **error );

%}

/* Associativity rules
 */

/* Token definitions
 */
%token XML_ATTRIBUTE_ASSIGN
%token XML_COMMENT
%token XML_DOCTYPE
%token XML_PROLOGUE
%token XML_TAG_END
%token XML_TAG_END_SINGLE

%token <string_value> XML_ATTRIBUTE_NAME
%token <string_value> XML_ATTRIBUTE_VALUE
%token <string_value> XML_TAG_CLOSE
%token <string_value> XML_TAG_CONTENT
%token <string_value> XML_TAG_OPEN_START

%%

/* Parser rules
 */

xml_plist_main
	: xml_prologue xml_doctype xml_tag_open xml_tags xml_tag_close
	;

xml_prologue
	: /* empty */
	| XML_PROLOGUE
	;

xml_doctype
	: /* empty */
	| XML_DOCTYPE
	;

xml_tags
	: /* empty */
	| xml_tag xml_tags
	;

xml_tag
	: xml_tag_open xml_tags xml_tag_close
	| xml_tag_open xml_tag_content xml_tag_close
	| xml_tag_single
	;

xml_tag_open_start
	: XML_TAG_OPEN_START
	{
		xml_parser_rule_print(
		 "xml_tag_open_start" );

		if( $1.data == NULL )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid tag name.",
			 xml_parser_function );

			YYABORT;
		}
		( (xml_parser_state_t *) parser_state )->current_tag = NULL;

		if( libfplist_xml_tag_initialize(
		     &( ( (xml_parser_state_t *) parser_state )->current_tag ),
		     (uint8_t *) $1.data,
		     $1.length,
		     ( (xml_parser_state_t *) parser_state )->error ) != 1 )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create XML tag.",
			 xml_parser_function );

			YYABORT;
		}
		if( ( (xml_parser_state_t *) parser_state )->root_tag == NULL )
		{
			( (xml_parser_state_t *) parser_state )->root_tag = ( (xml_parser_state_t *) parser_state )->current_tag;
		}
		else
		{
			if( libfplist_xml_tag_append_element(
			     ( (xml_parser_state_t *) parser_state )->parent_tag,
			     ( (xml_parser_state_t *) parser_state )->current_tag,
			     ( (xml_parser_state_t *) parser_state )->error ) != 1 )
			{
				libcerror_error_set(
				 ( (xml_parser_state_t *) parser_state )->error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
				 "%s: unable to append attribute.",
				 xml_parser_function );

				YYABORT;
			}
		}
		( (xml_parser_state_t *) parser_state )->parent_tag = ( (xml_parser_state_t *) parser_state )->current_tag;
	}
	;

xml_tag_open
	: xml_tag_open_start xml_attributes XML_TAG_END
	;

xml_tag_single
	: xml_tag_open_start xml_attributes XML_TAG_END_SINGLE
	{
		xml_parser_rule_print(
		 "xml_tag_single" );

		if( ( (xml_parser_state_t *) parser_state )->current_tag == NULL )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid current tag.",
			 xml_parser_function );

			YYABORT;
		}
		( (xml_parser_state_t *) parser_state )->parent_tag  = ( (xml_parser_state_t *) parser_state )->current_tag->parent_tag;
		( (xml_parser_state_t *) parser_state )->current_tag = ( (xml_parser_state_t *) parser_state )->parent_tag;
	}
	;

xml_tag_close
	: XML_TAG_CLOSE
	{
		xml_parser_rule_print(
		 "xml_tag_close" );

		if( $1.data == NULL )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid tag name.",
			 xml_parser_function );

			YYABORT;
		}
		if( ( (xml_parser_state_t *) parser_state )->current_tag == NULL )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid current tag.",
			 xml_parser_function );

			YYABORT;
		}
		if( ( ( (xml_parser_state_t *) parser_state )->current_tag->name_size != ( $1.length + 1 ) )
		 || ( narrow_string_compare(
		       ( (xml_parser_state_t *) parser_state )->current_tag->name,
		       $1.data,
		       $1.length ) != 0 ) )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: mismatch in tag name.",
			 xml_parser_function );

			YYABORT;
		}
		( (xml_parser_state_t *) parser_state )->parent_tag  = ( (xml_parser_state_t *) parser_state )->current_tag->parent_tag;
		( (xml_parser_state_t *) parser_state )->current_tag = ( (xml_parser_state_t *) parser_state )->parent_tag;
	}
	;

xml_tag_content
	: XML_TAG_CONTENT
	{
		xml_parser_rule_print(
		 "xml_tag_content" );

		if( $1.data == NULL )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid attribute value.",
			 xml_parser_function );

			YYABORT;
		}
		if( libfplist_xml_tag_set_value(
		     ( (xml_parser_state_t *) parser_state )->current_tag,
		     (uint8_t *) $1.data,
		     $1.length,
		     ( (xml_parser_state_t *) parser_state )->error ) != 1 )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to set value.",
			 xml_parser_function );

			YYABORT;
		}
	}
	;

xml_attributes
	: /* empty */
	| xml_attribute xml_attributes
	;

xml_attribute
	: XML_ATTRIBUTE_NAME XML_ATTRIBUTE_ASSIGN XML_ATTRIBUTE_VALUE
	{
		xml_parser_rule_print(
		 "xml_attribute" );

		if( $1.data == NULL )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid attribute name.",
			 xml_parser_function );

			YYABORT;
		}
		if( $3.data == NULL )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid attribute value.",
			 xml_parser_function );

			YYABORT;
		}
		if( libfplist_xml_tag_append_attribute(
		     ( (xml_parser_state_t *) parser_state )->current_tag,
		     (uint8_t *) $1.data,
		     $1.length,
		     (uint8_t *) $3.data,
		     $3.length,
		     ( (xml_parser_state_t *) parser_state )->error ) != 1 )
		{
			libcerror_error_set(
			 ( (xml_parser_state_t *) parser_state )->error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_APPEND_FAILED,
			 "%s: unable to append attribute.",
			 xml_parser_function );

			YYABORT;
		}
	}
	;

%%

int xml_parser_parse_buffer(
     libfplist_property_list_t *property_list,
     const uint8_t *buffer,
     size_t buffer_size,
     libcerror_error_t **error )
{
	xml_parser_state_t parser_state;
	
	YY_BUFFER_STATE buffer_state = NULL;
	static char *function        = "xml_parser_parse_buffer";
	size_t buffer_offset         = 0;
	int result                   = -1;

	buffer_state = xml_scanner__scan_buffer(
	                (char *) &( buffer[ buffer_offset ] ),
	                buffer_size - buffer_offset );

	xml_scanner_buffer_offset = (size_t) buffer_offset;

	if( buffer_state != NULL )
	{
		parser_state.property_list = property_list;
		parser_state.error         = error;
		parser_state.root_tag      = NULL;
		parser_state.current_tag   = NULL;
		parser_state.parent_tag    = NULL;

		if( xml_scanner_parse(
		     &parser_state ) == 0 )
		{
			if( libfplist_property_list_set_root_tag(
			     property_list,
			     parser_state.root_tag,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to set root tag.",
				 function );
			}
			else
			{
				result = 1;
			}
		}
		xml_scanner__delete_buffer(
		 buffer_state );
	}
	xml_scanner_lex_destroy();

	return( result );
}


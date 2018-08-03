/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_XML_SCANNER_LIBFPLIST_XML_PARSER_H_INCLUDED
# define YY_XML_SCANNER_LIBFPLIST_XML_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int xml_scanner_debug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    XML_ATTRIBUTE_ASSIGN = 258,
    XML_COMMENT = 259,
    XML_DOCTYPE = 260,
    XML_PROLOGUE = 261,
    XML_TAG_END = 262,
    XML_TAG_END_SINGLE = 263,
    XML_ATTRIBUTE_NAME = 264,
    XML_ATTRIBUTE_VALUE = 265,
    XML_TAG_CLOSE = 266,
    XML_TAG_CONTENT = 267,
    XML_TAG_OPEN_START = 268
  };
#endif
/* Tokens.  */
#define XML_ATTRIBUTE_ASSIGN 258
#define XML_COMMENT 259
#define XML_DOCTYPE 260
#define XML_PROLOGUE 261
#define XML_TAG_END 262
#define XML_TAG_END_SINGLE 263
#define XML_ATTRIBUTE_NAME 264
#define XML_ATTRIBUTE_VALUE 265
#define XML_TAG_CLOSE 266
#define XML_TAG_CONTENT 267
#define XML_TAG_OPEN_START 268

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
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


};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE xml_scanner_lval;

int xml_scanner_parse (void *parser_state);

#endif /* !YY_XML_SCANNER_LIBFPLIST_XML_PARSER_H_INCLUDED  */

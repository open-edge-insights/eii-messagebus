
/*
Copyright (c) 2020 Intel Corporation.

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

#include <safe_lib.h>
#include "cpuid-check.h"
#define DEST_SIZE 13

char* get_vendor(){
	uint32_t regs[4];
	static char vendor[13];
	asm volatile ("cpuid":"=a" (regs[0]), "=b" (regs[1]), "=c" (regs[3]), "=d" (regs[2]) : "a" (0), "c" (2));
	memcpy_s(vendor, DEST_SIZE, &regs[1], 4);
	memcpy_s(vendor+4, DEST_SIZE, &regs[2], 4);
	memcpy_s(vendor+8, DEST_SIZE, &regs[3], 4);
	vendor[12] = '\0';
	return vendor;
}

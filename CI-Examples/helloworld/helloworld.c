/* Copyright (C) 2023 Gramine contributors
 * SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>

int main(void) {
    FILE* f = fopen("test.txt", "r");
    if(f == NULL) {
	printf("Could not open file\n");
	return 0;
    }
    char str[10];
    fread(str, 1 , 9, f);
    str[9] = 0;
    printf("Hello, world: %s\n", str);
    return 0;
}

---
title: "Low Level C"
description: "Cheatsheet"
date: "2025-8-3"
---
## strtol
```c
#include <stdio.h>
#include <stdlib.h> // Required for strtol

int main() {
  const char *str1 = "12345";
  const char *str2 = "0xFF"; // Hexadecimal number
  const char *str3 =
      "   -789abc"; // With leading whitespace and trailing characters
  const char *str4 = "invalid_string";

  char *endptr; // Pointer to store the unconverted part of the string
  long int num;

  // Example 1: Basic decimal conversion
  num = strtol(str1, &endptr, 10);
  printf("String: \"%s\", Converted: %ld, Remaining: \"%s\"\n", str1, num,
         endptr);

  // Example 2: Hexadecimal conversion
  num = strtol(str2, &endptr, 16);
  printf("String: \"%s\", Converted: %ld, Remaining: \"%s\"\n", str2, num,
         endptr);

  // Example 3: String with leading whitespace and trailing characters
  num = strtol(str3, &endptr, 10);
  printf("String: \"%s\", Converted: %ld, Remaining: \"%s\"\n", str3, num,
         endptr);

  // Example 4: Invalid string (no valid number found)
  num = strtol(str4, &endptr, 10);
  if (endptr == str4) { // No conversion occurred
    printf("String: \"%s\", No valid number found.\n", str4);
  } else {
    printf("String: \"%s\", Converted: %ld, Remaining: \"%s\"\n", str4, num,
           endptr);
  }

  // Example 5: Using base 0 for auto-detection (decimal, octal, hex)
  const char *str5 = "0123";  // Octal
  const char *str6 = "0xABC"; // Hexadecimal
  num = strtol(str5, &endptr, 0);
  printf("String: \"%s\" (base 0), Converted: %ld, Remaining: \"%s\"\n", str5,
         num, endptr);
  num = strtol(str6, &endptr, 0);
  printf("String: \"%s\" (base 0), Converted: %ld, Remaining: \"%s\"\n", str6,
         num, endptr);

  return 0;
}
```
res:
```
String: "12345", Converted: 12345, Remaining: ""
String: "0xFF", Converted: 255, Remaining: ""
String: "   -789abc", Converted: -789, Remaining: "abc"
String: "invalid_string", No valid number found.
String: "0123" (base 0), Converted: 83, Remaining: ""
String: "0xABC" (base 0), Converted: 2748, Remaining: ""

```
## fread
```c
#include <stdio.h> // Required for file operations

int main() {
  FILE *file_pointer;   // Declare a file pointer
  char buffer[100];     // Declare a buffer to store the read data
  size_t elements_read; // To store the number of elements successfully read

  // Open the file "example.bin" in binary read mode ("rb")
  file_pointer = fopen("example.bin", "rb");

  // Check if the file was opened successfully
  if (file_pointer == NULL) {
    perror("Error opening file"); // Print an error message if opening fails
    return 1;                     // Indicate an error
  }

  // Read data from the file:
  // - buffer: destination to store the data
  // - 1: size of each element to read (in bytes)
  // - 10: number of elements to read
  // - file_pointer: the file stream to read from
  elements_read = fread(buffer, 1, 10, file_pointer); //or stdin

  // Print the number of elements read and the content (if applicable)
  printf("Successfully read %zu elements.\n", elements_read);
  // Note: If reading binary data, printing directly as a string might not be
  // meaningful For character data, you might add a null terminator and print as
  // a string: buffer[elements_read] = '\0'; printf("Read data: %s\n", buffer);

  // Close the file
  fclose(file_pointer);

  return 0; // Indicate successful execution
}
```

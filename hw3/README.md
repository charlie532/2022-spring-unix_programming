# Project3 - Extend the Mini Lib C to Handle Signals

## Introduction
In this homework, you have to extend the mini C library introduced in the class to support signal relevant system calls. You have to implement the following C library functions in Assembly and C using the syntax supported by yasm x86_64 assembler.
1. setjmp: prepare for long jump by saving the current CPU state. In addition, preserve the signal mask of the current process.
2. longjmp: perform the long jump by restoring a saved CPU state. In addition, restore the preserved signal mask.
3. signal and sigaction: setup the handler of a signal.
4. sigprocmask: can be used to block/unblock signals, and get/set the current signal mask.
5. sigpending: check if there is any pending signal.
6. alarm: setup a timer for the current process.
7. write: write to a file descriptor.
8. pause: wait for signal
9. sleep: sleep for a specified number of seconds
10. exit: cause normal process termination
11. strlen: calculate the length of the string, excluding the terminating null byte ('\0').
12. functions to handle sigset_t data type: sigemptyset, sigfillset, sigaddset, sigdelset, and sigismember.

The API interface is the same to what we have in the standard C library. However, because we are attempting to replace the standard C library, our test codes will only be linked against the library implemented in this homework. We will use the following commands to assemble, compile, link, and test your implementation.
```
$ make		# Use your provided Makefile to generate `libmini.so`
$ yasm -f elf64 -DYASM -D__x86_64__ -DPIC start.asm -o start.o
$ gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI test.c
$ ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o test test.o start.o -L. -L.. -lmini
```
- test.c: the testing code (prepared by the TAs).
- start.asm: the program start routine we have introduced in the class (prepared by the TAs). 

Please notice that there is a -nostdlib parameter passed to the compiler, which means that you could not use any existing functions implemented in the standard C library. Only the functions you have implemented in the libmini64.asm and libmini.c file can be used. In addition to your library source code, you also have to provide a corresponding libmini.h file. The testing codes will include this file and use the function prototypes and data types defined in the header file.

You can build your libsmini.so by the following commands:
```
$ yasm -f elf64 -DYASM -D__x86_64__ -DPIC libmini64.asm -o libmini64.o
$ gcc -c -g -Wall -fno-stack-protector -fPIC -nostdlib libmini.c
$ ld -shared -o libmini.so libmini64.o libmini.o
```
To ensure that your library can handle signals properly, your implemented setjmp function must save the signal mask of the current process in your customized jmp_buf data structure. The saved signal mask must be restored by the longjmp function. This requirement is different from the default setjmp/longjmp implementation.

### Test Cases
- ```write1```:
  ```
  $ make write1
  gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI write1.c
  ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o write1 write1.o start.o -L. -L.. -lmini
  rm write1.o
  $ LD_LIBRARY_PATH=. ./write1
  Hello world!
  ```
- ```alarm1.c```:
  ```
  $ make alarm1
  gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm1.c
  ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm1 alarm1.o start.o -L. -L.. -lmini
  rm alarm1.o
  $ LD_LIBRARY_PATH=. ./alarm1
  (3 seconds later ...)
  Alarm clock
  ```
- ```alarm2.c```:
  ```
  $ make alarm2
  gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm2.c
  ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm2 alarm2.o start.o -L. -L.. -lmini
  rm alarm2.o
  $ LD_LIBRARY_PATH=. ./alarm2
  (5 seconds later ...)
  sigalrm is pending.
  ```
- ```alarm3.c```:
  ```
  $ make alarm3
  gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm3.c
  ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.3 -o alarm3 alarm3.o start.o -L. -L.. -lmini
  rm alarm3.o
  $ LD_LIBRARY_PATH=. ./alarm3
  ^Csigalrm is pending.
  ```
- ```jmp1.c```:
  ```
  $ make jmp1
  gcc -o jmp1.o -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI jmp1.c
  ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o jmp1 jmp1.o start.o -L. -L.. -lmini
  rm jmp1.o
  $ LD_LIBRARY_PATH=. ./jmp1
  This is function a().
  This is function b().
  This is function c().
  This is function d().
  This is function e().
  This is function f().
  This is function g().
  This is function h().
  This is function i().
  This is function j().
  $
  ```


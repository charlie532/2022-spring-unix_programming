# Monitor File Activities of Dynamically Linked Programs
In this homework, we are going to practice library injection and API hijacking. Please implement a simple logger program that is able to show file-access-related activities of an arbitrary binary running on a Linux operating system. You have to implement your logger in two parts. One is a logger program that prepares the runtime environment to inject, load, and execute a monitored binary program. The other is a shared object that can be injected into a program by the *logger* using **LD_PRELOAD**. You have to dump the library calls as well as the passed parameters and the returned values. Please check the "Requirements" section for more details.

The output of your homework is required to strictly follow the spec. The TAs will use diff tool to compare the output of your program against the correct answer. Spaces and tabs in the output are compressed into a single space character when comparing the outputs.

## Program Arguments
Your program should work with the following arguments:
```
usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]
    -p: set the path to logger.so, default = ./logger.so
    -o: print output to file, print to "stderr" if no file specified
    --: separate the arguments for logger and for the command
```
The message should be displayed if an invalid argument is passed to the *logger*.

## Monitored file access activities
The list of monitored library calls is shown below. It covers several functions we have introduced in the class.
```
chmod chown close creat fclose fopen fread fwrite open read remove rename tmpfile write
```

## Output
You have to dump the library calls as well as the corresponding parameters and the return value. We have several special rules for printing out function arguments and return values:

* If a passed argument is a filename string, print the real absolute path of the file by using `realpath(3)`. If `realpath(3)` cannot resolve the filename string, simply print out the string untouched.
* If a passed argument is a descriptor or a FILE * pointer, print the absolute path of the corresponding file. The filename for a corresponding descriptor can be found in `/proc/{pid}/fd` directory.
* If a passed argument is a mode or a flag, print out the value in octal.
* If a passed argument is an integer, simply print out the value in decimal.
* If a passed argument is a regular character buffer, print it out up to 32 bytes. Check each output character using `isprint(3)` function and output a dot '.' if a character is not printable.
* If a return value is an integer, simply print out the value in decimal.
* If a return value is a pointer, print out it using `%p` format conversion specifier.
* Output strings should be quoted with double-quotes.

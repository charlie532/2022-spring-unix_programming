# Implement a 'lsof'-like program
In this homework, you have to implement the 'lsof' tool by yourself. 'lsof' is a tool to list open files. It can be used to list all the files opened by processes running in the system. The output of your homework is required to follow the spec strictly. The TAs will use the 'diff' tool to compare your output directly against our prepared sample test data.
## Program Arguments

* `-c REGEX`: a regular expression (REGEX) filter for filtering command line. For example `-c sh` would match `bash`, `zsh`, and `share`.
* `-t TYPE`: a TYPE filter. Valid TYPE includes `REG`, `CHR`, `DIR`, `FIFO`, `SOCK`, and `unknown`. TYPEs other than the listed should be considered as invalid. For invalid types, your program have to print out an error message `Invalid TYPE option`. in a single line and terminate your program.
* `-f REGEX`: a regular expression (REGEX) filter for filtering filenames.

A sample output from this homework is demonstrated as follows:
```
$ ./hw1  -c bash
bash
COMMAND PID     USER      	FD     TYPE     NODE     NAME      
bash    26884   terrynini38514	cwd    DIR      57779    /media/psf/Home/Desktop
bash    26884   terrynini38514	root   DIR      2        /         
bash    26884   terrynini38514	exe    REG      1179741  /usr/bin/bash
bash    26884   terrynini38514	mem    REG      1179741  /usr/bin/bash
bash    26884   terrynini38514	mem    REG      1186555  /usr/lib/x86_64-linux-gnu/libnss_files-2.31.so
bash    26884   terrynini38514	mem    REG      1185120  /usr/lib/locale/locale-archive
bash    26884   terrynini38514	mem    REG      1185791  /usr/lib/x86_64-linux-gnu/libc-2.31.so
bash    26884   terrynini38514	mem    REG      1185926  /usr/lib/x86_64-linux-gnu/libdl-2.31.so
bash    26884   terrynini38514	mem    REG      1186902  /usr/lib/x86_64-linux-gnu/libtinfo.so.6.2
bash    26884   terrynini38514	mem    REG      1708797  /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
bash    26884   terrynini38514	mem    REG      1185576  /usr/lib/x86_64-linux-gnu/ld-2.31.so
bash    26884   terrynini38514	0u     CHR      3        /dev/pts/0
bash    26884   terrynini38514	1u     CHR      3        /dev/pts/0
bash    26884   terrynini38514	2u     CHR      3        /dev/pts/0
bash    26884   terrynini38514	255u   CHR      3        /dev/pts/0
```
```
$ ./hw1 | head -n 20
COMMAND         PID             USER            FD              TYPE            NODE            NAME
systemd         1               root            cwd             unknown                         /proc/1/cwd (Permission denied)
systemd         1               root            rtd             unknown                         /proc/1/root (Permission denied)
systemd         1               root            txt             unknown                         /proc/1/exe (Permission denied)
systemd         1               root            NOFD                                            /proc/1/fd (Permission denied)
kthreadd                2               root            cwd             unknown                         /proc/2/cwd (Permission denied)
kthreadd                2               root            rtd             unknown                         /proc/2/root (Permission denied)
kthreadd                2               root            txt             unknown                         /proc/2/exe (Permission denied)
kthreadd                2               root            NOFD                                            /proc/2/fd (Permission denied)
rcu_gp          3               root            cwd             unknown                         /proc/3/cwd (Permission denied)
rcu_gp          3               root            rtd             unknown                         /proc/3/root (Permission denied)
rcu_gp          3               root            txt             unknown                         /proc/3/exe (Permission denied)
rcu_gp          3               root            NOFD                                            /proc/3/fd (Permission denied)
rcu_par_gp              4               root            cwd             unknown                         /proc/4/cwd (Permission denied)
rcu_par_gp              4               root            rtd             unknown                         /proc/4/root (Permission denied)
rcu_par_gp              4               root            txt             unknown                         /proc/4/exe (Permission denied)
rcu_par_gp              4               root            NOFD                                            /proc/4/fd (Permission denied)
kworker/0:0H-events_highpri             6               root            cwd             unknown                         /proc/6/cwd (Permission denied)
kworker/0:0H-events_highpri             6               root            rtd             unknown                         /proc/6/root (Permission denied)
kworker/0:0H-events_highpri             6               root            txt             unknown                         /proc/6/exe (Permission denied)
...
```

The detailed spec of this homework is introduced as follows. Your program has to output the following fields (columns) for each file opened by a running process. Each line presents the information for a single file. The required fields include `COMMAND`, `PID`, `USERM`, `FD`, `TYPE`, `NODE`, and `NAME`. The meaning of each field (column) is introduced below.

* `COMMAND`:
  * The executable filename of a running process.
  * DO NOT show arguments.
* `PID`:
  * Process id of a running process.
  * Only need to handle opened files in process level (check `/proc/[pid]`. No need to handle opened files in thread level (that would be in `/proc/[pid]/task/[tid]`).
* `USER`:
  * The username who run the process.
  * Please show `username` instead of UID.
* `FD`: The file descriptor. The value shown in `FD` field can be one of the following cases.
  * `cwd`: The current working directory, can be read from `/proc/[pid]/cwd`.
  * `root`: root directory, can be read from `/proc/[pid]/root`.
  * `exe`: program file of this process, can be read from `/proc/[pid]/exe`.
  * `mem`: memory mapping information, can be read from `/proc/[pid]/maps`.
    - If `/proc/<pid>/maps` is not accessible, you don't need to show any information about mapped files.
    - A memory-mapped file may have multiple segments or be mapped multiple times. You only need to output the first one for duplicated files, i.e., files having the same i-node or filename.
    - You don't need to handle memory segments that do not associate with a file. For example, [heap] or anonymously mapped memory segments. Those memory segments should have an i-node number of zero.
  * `del`: indicate that the file or link has been deleted. You should show this value if there is a (deleted) mark right after the filename in memory maps.
  * `[0-9]+[rwu]`: file descriptor and opened mode.
    - The numbers show the file descriptor number of the opened file.
    - The mode "r" means the file is opened for reading.
    - The mode "w" means the file is opened for writing.
    - The mode "u" means the file is opened for reading and writing.
  * `NOFD`: if `/proc/[pid]/fd` is not accessible. In this case, the values for `TYPE` and `NODE` field can be left empty.
* `TYPE`: The type of the opened file. The value shown in TYPE can be one of the following cases.
  * `DIR`: a directory. `cwd` and `root` is also classified as this type.
  * `REG`: a regular file
  * `CHR`: a character special file, for example
  
    ```crw-rw-rw- 1 root root 1, 3 Mar 17 17:31 /dev/null```

  * `FIFO`: a pipe, for examle
    - A link to a pipe, e.g.,

        ```lr-x------ 1 root root 64 Mar 17 19:55 5 -> 'pipe:[138394]'```

    - A file with `p` type (FIFO)
  
        ```prw------- 1 root root 0 Mar 17 19:54 /run/systemd/inhibit/11.ref```

  * `SOCK`: a socket, for example
    
    ```lrwx------ 1 root root 64 Mar 17 19:55 1 -> 'socket:[136975]'```

  * `unknown`: Any other unlisted types. Alternatively, if a file has been deleted or is not accessible (e.g., permission denied), this column can show `unknown`.
* `NODE`:
    * The i-node number of the file
    * It can be blank or empty if and only if `/proc/[pid]/fd` is not accessible.
* `NAME`:
  * Show the opened filename if it is a typical file or directory.
  * Show `pipe:[node number]` if it is a symbolic file to a pipe, e.g.,
    
    ```l-wx------ 1 ta ta 64 三 8 02:11 91 -> 'pipe:[2669735]'```

  * Show `socket:[node number]` if it is a symbolic file to a socket, e.g.,
    
    ```lrwx------ 1 ta ta 64 三 8 02:11 51 -> 'socket:[2669792]'```


  * Append  `(Permission denied)` if the access to `/proc/pid/fd` or `/proc/pid/(cwd|root|exe)` is failed due to permission denied.
  * If the filename you read from /proc file system contains a ` (deleted)`, please remove it from the filename before you print it out.
## Additional Notes on REGEX
If you plan to test REGEX feature with the `lsof` package that comes with Linux distributions, you should run it with the option `-c /REGEX/`.

For students who programming with C++, consider working with `regex_search()` instead of `regex_match()`. Please work with `regcomp()` and `regexec()` for students who are programming with C to implement this feature.

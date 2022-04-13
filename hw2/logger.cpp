#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h> // for library injection
#include <sys/types.h>
#include <gnu/lib-names.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>

using namespace std;

#define LIBC "libc.so.6"
#define MAX_PATH_LEN 512
#define MAX_BUFFER_SIZE 33

extern "C" {
    static int (*old_chmod)(const char *, mode_t) = NULL;
    static int (*old_creat)(const char *, mode_t) = NULL;
    static int (*old_creat64)(const char *, mode_t) = NULL;
    static int (*old_chown)(const char *, uid_t, gid_t) = NULL;
    static int (*old_remove)(const char *) = NULL;
    static int (*old_open)(const char *, int , ...) = NULL;
    static int (*old_open64)(const char *, int , ...) = NULL;
    static int (*old_rename)(const char *, const char *) = NULL;
    static ssize_t (*old_write)(int, const void *, size_t) = NULL;
    static ssize_t (*old_read)(int, const void *, size_t) = NULL;
    static int (*old_close)(int) = NULL;
    static size_t (*old_fread)(void *, size_t, size_t, FILE *) = NULL;
    static size_t (*old_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
    static FILE *(*old_fopen)(const char *, const char *) = NULL;
    static FILE *(*old_fopen64)(const char *, const char *) = NULL;
    static int (*old_fclose)(FILE *stream) = NULL;
    static FILE *(*old_tmpfile)(void) = NULL;
    static FILE *(*old_tmpfile64)(void) = NULL;

    char *buf_filter(const void *buf, char *new_buf) {
        const char *buf_ptr = (char*)buf;
        int i = 0;
        while (buf_ptr[i] != '\0' && i < 32) {
            if (isprint(buf_ptr[i])) {
                new_buf[i] = buf_ptr[i];
            } else {
                new_buf[i] = '.';
            }
            ++i;
        }
        new_buf[i] = '\0';

        return new_buf;
    }

    void *get_old_func(const char *cmd, void *handle) {
        char *error;
        if (handle) {
            return dlsym(handle, cmd);
        } else {
            fprintf(stderr, "%s\n", dlerror());
        }
        if ((error = dlerror()) != NULL) {
            fprintf(stderr, "%s\n", error);
        }

        return handle;
    }

    char *get_abs_path(const char *pathname, char *abs_path) {
        if (!realpath(pathname, abs_path)) {
            strcpy(abs_path, pathname);
        }

        return abs_path;
    }

    int chmod(const char *pathname, mode_t mode) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_chmod) = get_old_func("chmod", handle);

        int return_val = (*old_chmod)(pathname, mode);

        char temp_path[MAX_PATH_LEN];
        char *abs_path = get_abs_path(pathname, temp_path);
        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] chmod(\"%s\", %o) = %d\n", abs_path, mode, return_val);
        
        dlclose(handle);

        return return_val;
    }

    int creat(const char *pathname, mode_t mode) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_creat) = get_old_func("creat", handle);

        int return_val = (*old_creat)(pathname, mode);

        char temp_path[MAX_PATH_LEN];
        char *abs_path = get_abs_path(pathname, temp_path);
        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] creat(\"%s\", %o) = %d\n", abs_path, mode, return_val);
        
        dlclose(handle);

        return return_val;
    }

    int creat64(const char *pathname, mode_t mode) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_creat64) = get_old_func("creat64", handle);

        int return_val = (*old_creat64)(pathname, mode);

        char temp_path[MAX_PATH_LEN];
        char *abs_path = get_abs_path(pathname, temp_path);
        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] creat64(\"%s\", %o) = %d\n", abs_path, mode, return_val);
        
        dlclose(handle);

        return return_val;
    }

    int chown(const char *pathname, uid_t owner, gid_t group) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_chown) = get_old_func("chown", handle);

        int return_val = (*old_chown)(pathname, owner, group);

        char temp_path[MAX_PATH_LEN];
        char *abs_path = get_abs_path(pathname, temp_path);
        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] chown(\"%s\", %d, %d) = %d\n", abs_path, owner, group, return_val);
        
        dlclose(handle);

        return return_val;
    }

    int remove(const char *pathname) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_remove) = get_old_func("remove", handle);

        int return_val = (*old_remove)(pathname);

        char temp_path[MAX_PATH_LEN];
        char *abs_path = get_abs_path(pathname, temp_path);
        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] remove(\"%s\") = %d\n", abs_path, return_val);
        
        dlclose(handle);

        return return_val;
    }

    int open(const char *pathname, int flags, ...) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_open) = get_old_func("open", handle);

        mode_t mode = 0;
        if (__OPEN_NEEDS_MODE(flags)) {
            va_list arg;
            va_start(arg, flags);
            mode = va_arg(arg, mode_t);
            va_end (arg);
        }

        int return_val = (*old_open)(pathname, flags, mode);

        char temp_path[MAX_PATH_LEN];
        char *abs_path = get_abs_path(pathname, temp_path);
        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] open(\"%s\", %o, %o) = %d\n", abs_path, flags, mode, return_val);
        
        dlclose(handle);

        return return_val;
    }

    int open64(const char *pathname, int flags, ...) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_open64) = get_old_func("open64", handle);

        mode_t mode = 0;
        if (__OPEN_NEEDS_MODE(flags)) {
            va_list arg;
            va_start(arg, flags);
            mode = va_arg(arg, mode_t);
            va_end (arg);
        }

        int return_val = (*old_open64)(pathname, flags, mode);

        char temp_path[MAX_PATH_LEN];
        char *abs_path = get_abs_path(pathname, temp_path);
        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] open64(\"%s\" %o, %o) = %d\n", abs_path, flags, mode, return_val);
        
        dlclose(handle);

        return return_val;
    }

    int rename(const char *old_path, const char *new_path) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_rename) = get_old_func("rename", handle);

        char temp_path1[MAX_PATH_LEN];
        char *old_abs_path = get_abs_path(old_path, temp_path1);

        int return_val = (*old_rename)(old_path, new_path);

        char temp_path2[MAX_PATH_LEN];
        char *new_abs_path = get_abs_path(new_path, temp_path2);
        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] rename(\"%s\", \"%s\") = %d\n", old_abs_path, new_abs_path, return_val);
        
        dlclose(handle);

        return return_val;
    }

    ssize_t write(int fildes, const void *buf, size_t nbyte) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_write) = get_old_func("write", handle);

        char fd_path[MAX_PATH_LEN];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fildes);
        char abs_fd_path[MAX_PATH_LEN];
        memset(abs_fd_path, '\0', sizeof(abs_fd_path));
        readlink(fd_path, abs_fd_path, sizeof(abs_fd_path));

        ssize_t return_val = (*old_write)(fildes, buf, nbyte);

        char new_buf[MAX_BUFFER_SIZE];
        char *checked_buf = buf_filter(buf, new_buf);

        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] write(\"%s\", \"%s\", %zu) = %zd\n", abs_fd_path, checked_buf, nbyte, return_val);
        
        dlclose(handle);

        return return_val;
    }

    ssize_t read(int fildes, void *buf, size_t nbyte) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_read) = get_old_func("read", handle);

        ssize_t return_val = (*old_read)(fildes, buf, nbyte);

        char fd_path[MAX_PATH_LEN];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fildes);
        char abs_fd_path[MAX_PATH_LEN];
        memset(abs_fd_path, '\0', sizeof(abs_fd_path));
        readlink(fd_path, abs_fd_path, sizeof(abs_fd_path));

        char new_buf[MAX_BUFFER_SIZE];
        char *checked_buf = buf_filter(buf, new_buf);

        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] read(\"%s\", \"%s\", %zu) = %zd\n", abs_fd_path, checked_buf, nbyte, return_val);
        
        dlclose(handle);

        return return_val;
    }

    int close(int fildes) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_close) = get_old_func("close", handle);

        char fd_path[MAX_PATH_LEN];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fildes);
        char abs_fd_path[MAX_PATH_LEN];
        memset(abs_fd_path, '\0', sizeof(abs_fd_path));
        readlink(fd_path, abs_fd_path, sizeof(abs_fd_path));

        int return_val = (*old_close)(fildes);

        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] close(\"%s\") = %d\n", abs_fd_path, return_val);
        
        dlclose(handle);

        return return_val;
    }

    size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_fread) = get_old_func("fread", handle);

        char fd_path[MAX_PATH_LEN];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fileno(stream));
        char abs_fd_path[MAX_PATH_LEN];
        memset(abs_fd_path, '\0', sizeof(abs_fd_path));
        readlink(fd_path, abs_fd_path, sizeof(abs_fd_path));

        size_t return_val = (*old_fread)(ptr, size, nmemb, stream);

        char new_buf[MAX_BUFFER_SIZE];
        char *checked_buf = buf_filter(ptr, new_buf);

        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] fread(\"%s\", %zu, %zu, \"%s\") = %zu\n", checked_buf, size, nmemb, abs_fd_path, return_val);
        
        dlclose(handle);

        return return_val;
    }

    size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_fwrite) = get_old_func("fwrite", handle);

        char fd_path[MAX_PATH_LEN];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fileno(stream));
        char abs_fd_path[MAX_PATH_LEN];
        memset(abs_fd_path, '\0', sizeof(abs_fd_path));
        readlink(fd_path, abs_fd_path, sizeof(abs_fd_path));

        size_t return_val = (*old_fwrite)(ptr, size, nmemb, stream);

        char new_buf[MAX_BUFFER_SIZE];
        char *checked_buf = buf_filter(ptr, new_buf);

        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] fwrite(\"%s\", %zu, %zu, \"%s\") = %zu\n", checked_buf, size, nmemb, abs_fd_path, return_val);
        
        dlclose(handle);

        return return_val;
    }

    FILE *fopen(const char *pathname, const char *mode) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_fopen) = get_old_func("fopen", handle);

        FILE *return_val = (*old_fopen)(pathname, mode);

        char temp_path[MAX_PATH_LEN];
        char *abs_path = get_abs_path(pathname, temp_path);
        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] fopen(\"%s\", \"%s\") = %p\n", abs_path, mode, return_val);
        
        dlclose(handle);

        return return_val;
    }

    FILE *fopen64(const char *pathname, const char *mode) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_fopen64) = get_old_func("fopen64", handle);

        FILE *return_val = (*old_fopen64)(pathname, mode);

        char temp_path[MAX_PATH_LEN];
        char *abs_path = get_abs_path(pathname, temp_path);
        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] open64(\"%s\", \"%s\") = %p\n", abs_path, mode, return_val);
        
        dlclose(handle);

        return return_val;
    }

    int fclose(FILE *stream) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_fclose) = get_old_func("fclose", handle);

        char fd_path[MAX_PATH_LEN];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fileno(stream));
        char abs_fd_path[MAX_PATH_LEN];
        memset(abs_fd_path, '\0', sizeof(abs_fd_path));
        readlink(fd_path, abs_fd_path, sizeof(abs_fd_path));

        int return_val = (*old_fclose)(stream);

        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] fclose(\"%s\") = %d\n", abs_fd_path, return_val);
        
        dlclose(handle);

        return return_val;
    }

    FILE *tmpfile(void) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_tmpfile) = get_old_func("tmpfile", handle);

        FILE *return_val = (*old_tmpfile)();

        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] tmpfile() = %p\n", return_val);
        
        dlclose(handle);

        return return_val;
    }

    FILE *tmpfile64(void) {
        void *handle = dlopen(LIBM_SO, RTLD_LAZY);
        *(void **)(&old_tmpfile64) = get_old_func("tmpfile64", handle);

        FILE *return_val = (*old_tmpfile64)();

        char *fd = getenv("file_out");
        dprintf(atoi(fd), "[logger] tmpfile64() = %p\n", return_val);
        
        dlclose(handle);

        return return_val;
    }
}
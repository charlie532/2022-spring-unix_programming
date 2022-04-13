#include <sys/types.h> 
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <vector>

using namespace std;

struct option {
    bool type_o;
    bool type_p;
    char *arg_o;
    char *arg_p;
    vector<char*> cmd_arg;
};

void parse_arg(option &opt, int argc, char *argv[]) {
    if (argc < 2) {
        cout << "no command given." << endl;
        exit(0);
    }

    int cmd_opt;
    while ((cmd_opt = getopt(argc, argv, "o:p:")) != -1) {
        switch (cmd_opt) {
            case 'o':
                opt.type_o = true;
                opt.arg_o = optarg;
                break;
            case 'p':
                opt.type_p = true;
                opt.arg_p = optarg;
                break;
            default: 
                cout << "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]" << endl;
                cout << "    -p: set the path to logger.so, default = ./logger.so" << endl;
                cout << "    -o: print output to file, print to \"stderr\" if no file specified" << endl;
                cout << "    --: separate the arguments for logger and for the command" << endl;
                exit(0);
        }
    }
    for (int i = optind; i < argc; ++i) {
        opt.cmd_arg.push_back(argv[i]);
    }
    opt.cmd_arg.push_back(NULL);
}

string get_path(option opt) {
    string path;
    if (opt.type_p) {
        path = opt.arg_p;
    } else {
        path = "./logger.so";
    }

    return path;
}

void open_out_file(option opt) {
    if (opt.type_o) {
        int fd = open(opt.arg_o, O_RDWR|O_TRUNC|O_CREAT, S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH);
        if (fd < 0) {
            cerr << "open error." << endl;
        }

        setenv("file_out", to_string(fd).c_str(), true);

    } else {
        // print out to stderr
        dup2(2, 3);
        setenv("file_out", to_string(3).c_str(), true);
    }
}

int main(int argc, char *argv[]) {
    // parse args
    struct option opt = {
        .type_o = false,
        .type_p = false,
    };
    parse_arg(opt, argc, argv);
    
    pid_t pid = fork();
    if (pid == 0) {
        // set path of logger.so
        string so_path = get_path(opt);

        // open file
        open_out_file(opt);

        // set environment variable and execute cmd
        setenv("LD_PRELOAD", so_path.c_str(), true);
        execvp(argv[optind], &opt.cmd_arg[0]);

    } else if (pid > 0) {
        if (waitpid(pid, NULL, 0) != pid) {
            cerr << "wait error." << endl;
        }

    } else {
        cerr << "fork error." << endl;
    }
    
    return 0;
}
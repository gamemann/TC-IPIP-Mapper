#include <stdio.h>
#include <getopt.h>

#include "cmdline.h"

const struct option longopts[] =
{
    {"dev", required_argument, NULL, 'i'},
    {NULL, 0, NULL, 0}
};

void parsecmdline(int argc, char *argv[], struct cmdline *cmd)
{
    int i = -1;

    while ((i = getopt_long(argc, argv, "i:", longopts, NULL)) != -1)
    {
        switch (i)
        {
            case 'i':
                cmd->dev = optarg;

                break;

            case '?':
                fprintf(stderr, "Missing argument.\n");

                break;
        }
    }
}
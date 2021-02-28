#include <stdio.h>
#include <stdlib.h>

#include "cmdline.h"

int main(int argc, char *argv[])
{
    // Parse the command line and retrieve the interface we want to attach the TC programs to.
    struct cmdline cmd = {0};

    parsecmdline(argc, argv, &cmd);

    // Check to ensure interface isn't NULL.
    if (cmd.dev == NULL)
    {
        fprinf(stderr, "No interface specified. Pleasse specify an interface with the -i or --dev flag.\n");

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
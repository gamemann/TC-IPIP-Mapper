#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <string.h>

#include "cmdline.h"

#define CMD_MAX 2048
#define CMD_MAX_TC 256

uint8_t cont = 1;

void signhdl(int tmp)
{
    cont = 0;
}

int tc_attach(const char *dev, const char *hook, const char *bpf_obj, const char *sec_name)
{
    // Initialize variables.
    char cmd[CMD_MAX];
    int ret = 0;

    /* Delete clsact which also deletes existing programs. */

    // Set cmd to all 0's.
    memset(&cmd, 0, CMD_MAX);

    // Format command.
    snprintf(cmd, CMD_MAX, "tc qdisc del dev %s clsact 2> /dev/null", dev);

    // Call system command.
    ret = system(cmd);

    // Check if command executed.
    if (!WIFEXITED(ret)) 
    {
        fprintf(stderr, "Error attaching TC program (%s). Cannot execute TC command when removing clsact. Command => %s and Return Error Number => %d.\n", bpf_obj, cmd, WEXITSTATUS(ret));
    }

    /* Create clsact. */

    // Set cmd to all 0's.
    memset(&cmd, 0, CMD_MAX);

    // Format command.
    snprintf(cmd, CMD_MAX, "tc qdisc add dev %s clsact", dev);

    // Call system command.
    ret = system(cmd);

    // Check if command executed.
    if (ret) 
    {
        fprintf(stderr, "Error attaching TC program (%s). TC cannot create a clsact. Command => %s and Return Error Number => %d.\n", bpf_obj, cmd, WEXITSTATUS(ret));

        exit(1);
    }

    /* Attach TC program. */

    // Set cmd to all 0's.
    memset(&cmd, 0, CMD_MAX);

    // Format command.
    snprintf(cmd, CMD_MAX, "tc filter add dev %s %s prio 1 handle 1 bpf da obj %s sec %s", dev, hook, bpf_obj, sec_name);

    // Call system command.
    ret = system(cmd);

    // Check if command executed.
    if (ret) 
    {
        fprintf(stderr, "Error attaching TC program (%s). TC cannot attach to filter. Command => %s and Return Error Number => %d.\n", bpf_obj, cmd, WEXITSTATUS(ret));

        exit(1);
    }

    return ret;
}

int tc_detach(const char *dev, const char *hook)
{
    // Initialize starting variables.
    char cmd[CMD_MAX];
    int ret = 0;

    // Set cmd to all 0's.
    memset(&cmd, 0, CMD_MAX);

    // Format command.
    snprintf(cmd, CMD_MAX, "tc filter delete dev %s %s", dev, hook);

    // Call system command.
    ret = system(cmd);

    // Check if command executed.
    if (ret) 
    {
        fprintf(stderr, "Error detaching TC program (hook => %s). Command => %s and Return Error Number => %d.\n", hook, cmd, ret);

        exit(1);
    }

    return ret;
}

int main(int argc, char *argv[])
{
    // Parse the command line and retrieve the interface we want to attach the TC programs to.
    struct cmdline cmd = {0};

    parsecmdline(argc, argv, &cmd);

    // Check to ensure interface isn't NULL.
    if (cmd.dev == NULL)
    {
        fprintf(stderr, "No interface specified. Please specify an interface with the -i or --dev flag.\n");

        return EXIT_FAILURE;
    }

    // Attempt to attach TC programs.
    int err = 0;

    if ((err = tc_attach(cmd.dev, "ingress", "/etc/IPIPMapper/tc_mapper.o", "mapper")) != 0)
    {
        return err;
    }

    if ((err = tc_attach(cmd.dev, "egress", "/etc/IPIPMapper/tc_out.o", "out")) != 0)
    {
        // Detach Mapper.
        tc_detach(cmd.dev, "ingress");

        return err;
    }

    fprintf(stdout, "Successfully loaded TC programs! Please end program to detach TC programs.\n");

    signal(SIGINT, signhdl);

    // Create while loop.
    while (cont)
    {
        sleep(1);
    }

    // Attempt to detach TC programs.
    tc_detach(cmd.dev, "ingress");
    tc_detach(cmd.dev, "egress");

    return EXIT_SUCCESS;
}
#pragma once

struct cmdline
{
    char *dev;
};

void parsecmdline(int argc, char *argv[], struct cmdline *cmd);
#ifndef OOT_STARTUP_CLI_H
#define OOT_STARTUP_CLI_H
#include <stddef.h>
#include <stdint.h>
typedef struct OotStartupProbe { uint64_t address, value; } OotStartupProbe;
/* Returns -1 when this is not a startup command. */
int oot_startup_cli(int argc, char **argv);
#endif

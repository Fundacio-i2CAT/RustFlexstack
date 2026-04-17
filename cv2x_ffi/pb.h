/*
 * Minimal nanopb stub — provides just enough for v2x_common.pb.h to compile.
 * The legacy C-V2X API headers reference nanopb types in extern declarations
 * we never call, so only the type definitions are needed.
 */
#ifndef PB_H_INCLUDED
#define PB_H_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PB_PROTO_HEADER_VERSION 30

typedef uint32_t pb_field_t;

#endif /* PB_H_INCLUDED */

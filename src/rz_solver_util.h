// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#ifndef RZ_SOLVER_UTIL_H
#define RZ_SOLVER_UTIL_H

#include <rz_core.h>
#include <z3.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HEX_STR_HEADER "0x"
/**
 * \file rz_solver.h
 * \brief SMT APIs and structures..
 *
 * This file contains definitions, structures, and function prototypes for handling SMT APIs
 */
RZ_API Z3_context mk_context();

RZ_API Z3_solver mk_solver(Z3_context ctx);

RZ_API Z3_ast mk_int_var(Z3_context ctx, const char *name);

RZ_API Z3_ast mk_int(Z3_context ctx, int v);

RZ_API void check2(Z3_context ctx, Z3_solver s, Z3_lbool expected_result);

RZ_API void del_solver(Z3_context ctx, Z3_solver s);

RZ_API void display_ast(Z3_context c, const Z3_ast v);
 RZ_API Z3_ast mk_var(Z3_context ctx, const char *name, const Z3_sort ty);

#ifdef __cplusplus
}
#endif
#endif //RZ_SOLVER_UTIL_H


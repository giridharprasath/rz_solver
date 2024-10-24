// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: MIT

#ifndef RZ_SOLVER_UTIL_H
#define RZ_SOLVER_UTIL_H

#include <rz_core.h>
#include <z3.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file rz_solver.h
 * \brief SMT APIs and structures..
 *
 * This file contains definitions, structures, and function prototypes for
 * handling SMT APIs
 */

#define HEX_STR_HEADER "0x"
// Solver util APIs
RZ_API Z3_context rz_solver_mk_context();
RZ_API Z3_solver rz_solver_mk_solver(Z3_context ctx);
RZ_API Z3_ast mk_int_var(Z3_context ctx, const char *name);
RZ_API Z3_ast mk_int(Z3_context ctx, st64 value);
RZ_API void check2(Z3_context ctx, Z3_solver solver, Z3_lbool expected_result);
RZ_API void del_solver(Z3_context ctx, Z3_solver solver);
RZ_API void del_context(Z3_context ctx);
RZ_API Z3_ast mk_var(Z3_context ctx, const char *name, Z3_sort ty);
RZ_API Z3_ast mk_real_var(Z3_context ctx, const char *name);
RZ_API Z3_ast mk_unary_app(Z3_context ctx, Z3_func_decl func, Z3_ast ast);
RZ_API void display_model(Z3_context ctx, Z3_model model);
RZ_API void display_ast(Z3_context ctx, Z3_ast ast);
#ifdef __cplusplus
}
#endif
#endif // RZ_SOLVER_UTIL_H

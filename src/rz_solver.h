// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_SOLVER_LIBRARY_H
#define RZ_SOLVER_LIBRARY_H

#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_rop.h>

typedef struct rz_rop_solver_result_t {
  HtPU *constraint_result;
  RzPVector /*<ut64>*/ *gadget_info_addr_set;
  bool is_solved;
} RzRopSolverResult;

RZ_API RzCmdStatus rz_rop_solver(
    const RzCore *core, RzPVector /*<RzRopConstraint *>*/ *constraints);

// RzRopSolverResult APIs
RZ_API RzRopSolverResult *rz_rop_solver_result_new(void);
RZ_API void rz_rop_solver_result_free(RzRopSolverResult *result);
RZ_API void rz_rop_solver_result_print(const RzRopSolverResult *result);

#endif // RZ_SOLVER_LIBRARY_H

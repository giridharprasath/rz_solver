// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: MIT

#ifndef RZ_SOLVER_LIBRARY_H
#define RZ_SOLVER_LIBRARY_H

#include <rz_cmd.h>
#include <rz_core.h>
#include <z3.h>

#define MAX_GADGETS 10
#define MAX_GADGET_NODE_NAME 20
#define MAX_GADGET_NODE_RW 20

typedef struct {
    ut64 address;
  char name[MAX_GADGET_NODE_NAME];
  char writes[MAX_GADGET_NODE_RW][MAX_GADGET_NODE_RW];
  int writes_count;
  char reads[MAX_GADGET_NODE_RW][MAX_GADGET_NODE_RW];
  int reads_count;
} RzRopGadgetNode;

typedef struct {
  int adj[MAX_GADGETS][MAX_GADGETS];
  int num_vertices;
  RzRopGadgetNode gadgets[MAX_GADGETS];
} RzRopGraph;

typedef struct rz_rop_constraint_t RzRopExpression;

typedef struct rz_rop_solver_result_t {
  HtPU *constraint_result;
  RzRopGraph *graph;
  RzPVector /*<RzRopExpression *>*/ *rop_expressions;
  RzPVector /*<ut64>*/ *gadget_info_addr_set;
  bool is_solved;
  Z3_context ctx;
  Z3_solver solver;
} RzRopSolverResult;

RZ_API RzRopSolverResult *
rz_rop_solver(const RzCore *core,
              RzPVector /*<RzRopConstraint *>*/ *constraints);

// RzRopSolverResult APIs
RZ_API RzRopSolverResult *rz_rop_solver_result_new(void);
RZ_API void rz_rop_solver_result_free(RzRopSolverResult *result);
RZ_API void rz_rop_solver_result_print(const RzRopSolverResult *result);

#endif // RZ_SOLVER_LIBRARY_H

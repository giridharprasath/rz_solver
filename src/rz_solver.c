// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: MIT

#include "rz_solver.h"
#include "rz_solver_util.h"
#include <rz_core.h>
#include <rz_rop.h>
#include <z3.h>

/**
 * \file rz_solver.c
 * ROP Solver implementation.
 */

typedef struct {
  RzCore *core;
  const RzPVector *constraints;
  RzRopSolverResult *result;
} RopSolverCallbackParams;

// Struct for stack constraint query params
typedef struct {
  const RzCore *core;
  const RzRopConstraint *constraint;
  const RzRopRegInfo *reg_info;
  const RzRopGadgetInfo *gadget_info;
} RopStackConstraintParams;

typedef struct {
  ut64 analysis_level;
  RzCore *core;
  const RzRopConstraint *constraint;
  RzRopGadgetInfo *gadget_info;
  RzRopSolverResult *result;
} RopSolverAnalysisOpParams;

static void handle_analysis(RopSolverAnalysisOpParams *op_params);

static void update_rop_constraint_result(const RzRopSolverResult *result,
                                         const RzRopConstraint *constraint,
                                         const ut64 address) {
  rz_return_if_fail(result);
  rz_pvector_push(result->gadget_info_addr_set, (void *)address);
  rz_pvector_empty(result->rop_expressions);
  if (!ht_pu_update(result->constraint_result, constraint, 1)) {
    rz_warn_if_reached();
  }
}

static ut64 parse_rop_constraint_int_val(const RzRopConstraint *rop_constraint,
                                         const RzRopArgType type) {
  const char *src_const = rop_constraint->args[type];
  char *endptr;
  ut64 src_val;
  if (!strncmp(src_const, HEX_STR_HEADER, 2)) {
    src_val = strtoul(src_const, &endptr, 16);
  } else {
    src_val = strtoul(src_const, &endptr, 10);
  }

  if (src_const == endptr) {
    return -1;
  }

  return src_val;
}

static int add_gadget_to_graph(RzRopGraph *g, RzRopGadgetNode *gadget_node) {
  if (g->num_vertices >= MAX_GADGETS) {
    return -1;
  }

  int index = g->num_vertices;
  g->gadgets[index] = *gadget_node;
  g->num_vertices++;

  // Update dependencies with existing gadgets
  for (int i = 0; i < g->num_vertices - 1; i++) {
    // Check if the new gadget writes to registers read by existing gadgets
    for (int w = 0; w < gadget_node->writes_count; w++) {
      for (int r = 0; r < g->gadgets[i].reads_count; r++) {
        if (strcmp(gadget_node->writes[w], g->gadgets[i].reads[r]) == 0) {
          // Add edge from new gadget to existing gadget (index -> i)
          g->adj[index][i] = 1;
        }
      }
    }

    // Check if existing gadgets write to registers read by the new gadget
    for (int w = 0; w < g->gadgets[i].writes_count; w++) {
      for (int r = 0; r < gadget_node->reads_count; r++) {
        if (strcmp(g->gadgets[i].writes[w], gadget_node->reads[r]) == 0) {
          // Add edge from existing gadget to new gadget (i -> index)
          g->adj[i][index] = 1;
        }
      }
    }
  }

  return index;
}

static RzRopGraph *init_rz_rop_graph() {
  RzRopGraph *g = RZ_NEW0(RzRopGraph);
  if (!g) {
    return NULL;
  }

  g->num_vertices = 0;
  memset(g->adj, 0, sizeof(g->adj));
  memset(g->gadgets, 0, sizeof(g->gadgets));
  return g;
}

// Add a directed edge from u to v (u -> v)
void add_edge(RzRopGraph *g, int u, int v) {
  if (u >= 0 && u < g->num_vertices && v >= 0 && v < g->num_vertices) {
    g->adj[u][v] = 1;
  }
}

bool topological_sort(RzRopGraph *g, int sorted_order[]) {
  int in_degree[MAX_GADGETS] = {0};
  int num_vertices = g->num_vertices;

  // Calculate in-degrees of all vertices
  for (int i = 0; i < num_vertices; i++) {
    for (int j = 0; j < num_vertices; j++) {
      if (g->adj[j][i]) {
        in_degree[i]++;
      }
    }
  }

  int queue[MAX_GADGETS], front = 0, rear = -1;
  int index = 0; // Index for sorted_order

  // Enqueue all vertices with in-degree 0
  for (int i = 0; i < num_vertices; i++) {
    if (in_degree[i] == 0) {
      queue[++rear] = i;
    }
  }

  // Perform the sorting
  while (front <= rear) {
    int v = queue[front++];
    sorted_order[index++] = v;

    for (int i = 0; i < num_vertices; i++) {
      if (g->adj[v][i]) {
        in_degree[i]--;
        if (in_degree[i] == 0) {
          queue[++rear] = i;
        }
      }
    }
  }

  if (index != num_vertices) {
    // Graph has a cycle; topological sort not possible
    return false;
  }

  return true;
}

static ut8 *update_analysis_cache(RzCore *core, RzRopGadgetInfo *gadget_info) {
  rz_return_val_if_fail(core && core->analysis, false);
  // rop_gadget_info->size - 1 neglecting the ret instruction.

  ut64 size = gadget_info->size - 1;
  ut8 *buf = RZ_NEWS0(ut8, size);
  if (!buf) {
    return NULL;
  }
  if (rz_io_nread_at(core->io, gadget_info->address, buf, size) < 0) {
    free(buf);
    return NULL;
  }
  RzIterator *iter =
      rz_core_analysis_bytes(core, gadget_info->address, buf, size, 0);
  if (!iter) {
    free(buf);
    return NULL;
  }
  gadget_info->analysis_cache = iter;
  return buf;
}

void handle_analysis(RopSolverAnalysisOpParams *op_params);

static void *fill_gadget_analysis(RzRopConstraint *constraint, RzRopGadgetNode *gadget_node) {

  switch (constraint->type) {
  case MOV_CONST: {
    // reg <- const (SRC_CONST -> DST_REG)
    strcpy(gadget_node->writes[gadget_node->writes_count++],
           constraint->args[DST_REG]);
    break;
  }
  case MOV_REG: {
    strcpy(gadget_node->writes[gadget_node->writes_count++],
           constraint->args[DST_REG]);
    strcpy(gadget_node->reads[gadget_node->reads_count++],
           constraint->args[SRC_REG]);
    break;
  }
  case MOV_OP_CONST: {
    // reg <- reg OP const (SRC_REG -> DST_REG with operation and constant)
    strcpy(gadget_node->writes[gadget_node->writes_count++],
           constraint->args[DST_REG]);
    strcpy(gadget_node->reads[gadget_node->reads_count++],
           constraint->args[SRC_REG]);
    break;
  }
  case MOV_OP_REG: {
    // reg <- reg OP reg (SRC_REG -> DST_REG with operation and another reg)
    strcpy(gadget_node->writes[gadget_node->writes_count++],
           constraint->args[DST_REG]);
    strcpy(gadget_node->reads[gadget_node->reads_count++],
           constraint->args[SRC_REG]);
    strcpy(gadget_node->reads[gadget_node->reads_count++],
           constraint->args[SRC_REG_SECOND]);
    break;
  }
  default:
    break;
  }
}

static RzRopGadgetNode *construct_gadgets(RopSolverAnalysisOpParams *op_params,
                              RzRopExpression *expr,
                              RzRopGadgetNode *gadget_node) {
  if (!expr) {
    return NULL;
  }

  RzRopSolverResult *result = op_params->result;
  if (!rz_pvector_contains(result->rop_expressions, expr)) {
    rz_pvector_push(result->rop_expressions, expr);
    if (!gadget_node) {
        gadget_node = RZ_NEW0(RzRopGadgetNode);
        if (!gadget_node) {
            return NULL;
        }
    }
    fill_gadget_analysis(expr, gadget_node);
    return gadget_node;
  }

}

// Update this
static inline bool is_pure_op(const RzAnalysisOp *op) {
  const _RzAnalysisOpType type = (op->type & RZ_ANALYSIS_OP_TYPE_MASK);
  return type == RZ_ANALYSIS_OP_TYPE_ADD || type == RZ_ANALYSIS_OP_TYPE_SUB ||
         type == RZ_ANALYSIS_OP_TYPE_MUL || type == RZ_ANALYSIS_OP_TYPE_DIV ||
         type == RZ_ANALYSIS_OP_TYPE_MOD || type == RZ_ANALYSIS_OP_TYPE_AND ||
         type == RZ_ANALYSIS_OP_TYPE_OR || type == RZ_ANALYSIS_OP_TYPE_XOR ||
         type == RZ_ANALYSIS_OP_TYPE_SHL || type == RZ_ANALYSIS_OP_TYPE_SHR ||
         type == RZ_ANALYSIS_OP_TYPE_SAR;
}

static void
handle_mov_reg_analysis(const RopSolverAnalysisOpParams *op_params) {
  rz_return_if_fail(op_params && op_params->constraint &&
                    op_params->gadget_info);
  const RzRopConstraint *constraint = op_params->constraint;
  const char *dst_reg = constraint->args[DST_REG];
  if (!dst_reg) {
    return;
  }
  const RzRopGadgetInfo *gadget_info = op_params->gadget_info;
}

static void handle_mov_const_analysis(RopSolverAnalysisOpParams *op_params) {
  rz_return_if_fail(op_params && op_params->constraint && op_params &&
                    op_params->result && op_params->core);
  const RzRopConstraint *constraint = op_params->constraint;
  const RzRopGadgetInfo *gadget_info = op_params->gadget_info;
  if (!gadget_info) {
    return;
  }

  const char *dst_reg = constraint->args[DST_REG];
  if (!dst_reg) {
    return;
  }

    RzPVector *reg_info_event = rz_core_rop_gadget_get_reg_info_by_event(gadget_info, RZ_ROP_EVENT_MEM_READ);
    if (rz_pvector_len(reg_info_event) != 1) {
        return;
    }
    RzRopRegInfo *reg_info = rz_pvector_pop(reg_info_event);
    bool has_sp_modified = rz_core_rop_gadget_info_has_register(gadget_info, reg_info->name);
    if (!rz_reg_is_role(op_params->core->analysis->reg, reg_info->name, RZ_REG_NAME_SP) && has_sp_modified) {
        return;
    }
    reg_info_event = rz_core_rop_gadget_get_reg_info_by_event(gadget_info,
                                                              RZ_ROP_EVENT_MEM_WRITE);
    if (!rz_pvector_empty(reg_info_event)) {
        return;
    }
    bool has_dst_reg_modified = rz_core_rop_gadget_info_has_register(gadget_info, constraint->args[DST_REG]);
    if (rz_pvector_len(gadget_info->modified_registers) != 2 && has_dst_reg_modified) {
        return;
    }
    const ut64 src_const = parse_rop_constraint_int_val(constraint, SRC_CONST);
  RzIterator *iter = gadget_info->analysis_cache;
  RzAnalysisBytes *ab = rz_iterator_next(iter);
  RzRopGadgetNode *gadget_node = NULL;
  while (ab) {
    const RzAnalysisOp *op = ab->op;
    RzRopExpression *rop_expr =
        rop_constraint_parse_args(op_params->core, ab->pseudo);
    if (!rop_expr) {
      break;
    }
    gadget_node = construct_gadgets(op_params, rop_expr, gadget_node);
    if (!gadget_node) {
      break;
    }
    gadget_node->address = op_params->gadget_info->address;
    ab = rz_iterator_next(iter);
  }
    add_gadget_to_graph(op_params->result->graph, gadget_node);
    int sorted_order[MAX_GADGETS];
    topological_sort(op_params->result->graph, sorted_order);
    for (int i = 0; i < op_params->result->graph->num_vertices; i++) {
        int gadget_index = sorted_order[i];
        RzRopGadgetNode *gadget = &op_params->result->graph->gadgets[gadget_index];
    }

    return;
}

static void handle_analysis(RopSolverAnalysisOpParams *op_params) {
  op_params->analysis_level++;
  if (op_params->analysis_level > 2) {
    return;
  }
  if (!op_params->result) {
    return;
  }

  ut8 *buf = update_analysis_cache(op_params->core, op_params->gadget_info);
    if (!buf) {
      return;
    }

  if (!op_params->result->graph) {
    op_params->result->graph = init_rz_rop_graph();
    if (!op_params->result->graph) {
      return;
    }
  }

  const RzRopConstraint *constraint = op_params->constraint;
  switch (constraint->type) {
  case MOV_CONST:
    handle_mov_const_analysis(op_params);
  case MOV_REG:
    handle_mov_reg_analysis(op_params);
    break;
  default:
    break;
  }
  free(buf);
}

static bool has_value_cb(void *user, const void *key, const ut64 value) {
  RzRopSolverResult *result = user;
  if (!value) {
    result->is_solved = false;
    return false; // If it has one value, break from the loop
  }
  result->is_solved = true;
  return true;
}

static bool is_rop_solver_complete(const RzRopSolverResult *result) {
  rz_return_val_if_fail(result, false);
  ht_pu_foreach(result->constraint_result, has_value_cb, (void *)result);
  return result->is_solved;
}

static bool stack_constraint(const RopStackConstraintParams *params,
                             const RzRopSolverResult *result) {
  rz_return_val_if_fail(params && params->constraint && params->reg_info,
                        false);
  const RzCore *core = params->core;
  rz_return_val_if_fail(core && core->analysis && core->analysis->reg, false);

  bool status = false;
  const RzRopGadgetInfo *gadget_info = params->gadget_info;
  if (!gadget_info) {
    return status;
  }
  const char *sp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
  if (!sp) {
    return status;
  }
  // Check if a pop or an equivalent operation on stack has been performed
  if (gadget_info->stack_change <= core->analysis->bits / 8) {
    return status;
  }
  RzListIter *iter;
  RzRopRegInfo *reg_info;
  bool is_stack_constraint = true;
  rz_list_foreach(gadget_info->dependencies, iter, reg_info) {
    if (RZ_STR_NE(reg_info->name, sp) &&
        RZ_STR_NE(reg_info->name, params->reg_info->name)) {
      is_stack_constraint = false;
      break;
    }
  }

  if (!is_stack_constraint) {
    return status;
  }
  RzPVector /*<char *>*/ *query = rz_pvector_new(NULL);
  rz_pvector_push(query, (void *)params->reg_info->name);
  RzPVector /*<RzRopRegInfo *>*/ *stack_query =
      rz_core_rop_get_reg_info_by_reg_names(gadget_info, query);
  if (rz_pvector_empty(stack_query)) {
    goto exit;
  }
  void **it;
  rz_pvector_foreach(gadget_info->modified_registers, it) {
    const RzRopRegInfo *reg_info_iter = *it;
    if (!rz_pvector_contains(stack_query, reg_info_iter) &&
        RZ_STR_NE(reg_info_iter->name, sp)) {
      goto exit;
    }
  }
  // This gadget has pop register with no dependencies
  if (gadget_info->stack_change == core->analysis->bits / 8 * 2) {
    update_rop_constraint_result(result, params->constraint,
                                 gadget_info->address);
    status = true;
  }

exit:
  rz_pvector_fini(query);
  rz_pvector_fini(stack_query);
  return status;
}

static bool is_direct_lookup(const RzCore *core,
                             const RzRopGadgetInfo *gadget_info,
                             RzPVector *dep_allow_list) {
  if (!gadget_info) {
    return false;
  }

  if (rz_pvector_len(gadget_info->modified_registers) != 2) {
    return false;
  }

  RzRopRegInfo *reg_info = NULL;
  RzListIter *iter;
  if (dep_allow_list) {
    RzPVector *events = rz_core_rop_gadget_get_reg_info_by_event(
        gadget_info, RZ_ROP_EVENT_VAR_READ);
    if (rz_pvector_empty(events)) {
      return false;
    }
    while (!rz_pvector_empty(events)) {
      reg_info = rz_pvector_pop(events);
      if (!reg_info) {
        continue;
      }
      if (rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_SP) ||
          rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_BP)) {
        continue;
      }
      if (rz_pvector_find(dep_allow_list, reg_info->name,
                          (RzPVectorComparator)strcmp, NULL)) {
        return true;
      }
    }

    return false;
  }

  rz_list_foreach(gadget_info->dependencies, iter, reg_info) {
    if (rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_SP) ||
        rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_BP)) {
      continue;
    }
    return false;
  }

  return true;
}

static void rz_solver_mov_const_direct_lookup(
    const RzCore *core, const RzRopGadgetInfo *gadget_info,
    const RzRopConstraint *rop_constraint, const RzRopSolverResult *result) {
  RzRopRegInfo *info = rz_core_rop_gadget_info_get_modified_register(
      gadget_info, rop_constraint->args[DST_REG]);
  if (!info) {
    return;
  }

  // Direct lookup case
  const ut64 src_val = parse_rop_constraint_int_val(rop_constraint, SRC_CONST);
  if (src_val == -1) {
    return;
  }
  const bool is_dir_lookup = is_direct_lookup(core, gadget_info, NULL);
  if (info->new_val == src_val && is_dir_lookup) {
    update_rop_constraint_result(result, rop_constraint, gadget_info->address);
    return;
  }

  // Strategy: Search whether we can change the value through stack regs
  const RopStackConstraintParams stack_params = {
      .core = core,
      .constraint = rop_constraint,
      .reg_info = info,
      .gadget_info = gadget_info,
  };
  if (stack_constraint(&stack_params, result)) {
    return;
  }
}

static void rz_solver_mov_reg_direct_lookup(
    const RzCore *core, const RzRopGadgetInfo *gadget_info,
    const RzRopConstraint *rop_constraint, const RzRopSolverResult *result) {
  RzRopRegInfo *dst_info = rz_core_rop_gadget_info_get_modified_register(
      gadget_info, rop_constraint->args[DST_REG]);

  if (!dst_info) {
    return;
  }
  RzPVector *dep_allow_list = rz_pvector_new(free);
  if (!dep_allow_list) {
    return;
  }
  rz_pvector_push(dep_allow_list, rz_str_dup(rop_constraint->args[SRC_REG]));
  const bool is_dir_lookup =
      is_direct_lookup(core, gadget_info, dep_allow_list);
  if (is_dir_lookup) {
    update_rop_constraint_result(result, rop_constraint, gadget_info->address);
    goto exit;
  }

exit:
  rz_pvector_fini(dep_allow_list);
}

static void rz_solver_direct_lookup(const RzCore *core,
                                    const RzRopGadgetInfo *gadget_info,
                                    const RzRopConstraint *rop_constraint,
                                    const RzRopSolverResult *result) {
  if (!rop_constraint) {
    return;
  }
  switch (rop_constraint->type) {
  case MOV_CONST:
    return rz_solver_mov_const_direct_lookup(core, gadget_info, rop_constraint,
                                             result);
  case MOV_REG:
    return rz_solver_mov_reg_direct_lookup(core, gadget_info, rop_constraint,
                                           result);
  default:
    break;
  }
}

static void mov_const(RzCore *core, RzRopGadgetInfo *gadget_info,
                      const RzRopConstraint *rop_constraint,
                      const RopSolverCallbackParams *callback_params) {
  // Assertions for mov_const solver
  rz_return_if_fail(rop_constraint->args[SRC_CONST] &&
                    rop_constraint->args[DST_REG]);
  rz_return_if_fail(core && core->analysis && core->analysis->reg);
  if (is_rop_solver_complete(callback_params->result)) {
    return;
  }
  // Direct lookup case
  rz_solver_direct_lookup(core, gadget_info, rop_constraint,
                          callback_params->result);
  if (is_rop_solver_complete(callback_params->result)) {
    return;
  }
  RopSolverAnalysisOpParams analysis_op_params = {.core = core,
                                                  .constraint = rop_constraint,
                                                  .gadget_info = gadget_info,
                                                  .result =
                                                      callback_params->result,
                                                  .analysis_level = 0};

  handle_analysis(&analysis_op_params);

  // Recipe : Search for dependencies and create a z3 state
}

static void mov_reg(const RzCore *core, const RzRopGadgetInfo *gadget_info,
                    const RzRopConstraint *rop_constraint,
                    const RopSolverCallbackParams *callback_params) {
  // Assertions for mov_reg solver
  rz_return_if_fail(gadget_info && rop_constraint);
  rz_return_if_fail(rop_constraint->args[SRC_REG] &&
                    rop_constraint->args[DST_REG]);
  rz_return_if_fail(core && core->analysis && core->analysis->reg);

  RzRopRegInfo *info = rz_core_rop_gadget_info_get_modified_register(
      gadget_info, rop_constraint->args[DST_REG]);
  if (!info) {
    return;
  }
  // Direct lookup case
  rz_solver_direct_lookup(core, gadget_info, rop_constraint,
                          callback_params->result);
  if (is_rop_solver_complete(callback_params->result)) {
    return;
  }
}

void prove(Z3_context ctx, Z3_solver s, Z3_ast f, bool is_valid) {
  Z3_model m = 0;
  Z3_ast not_f;
  /* save the current state of the context */
  Z3_solver_push(ctx, s);

  not_f = Z3_mk_not(ctx, f);
  Z3_solver_assert(ctx, s, not_f);

  switch (Z3_solver_check(ctx, s)) {
  case Z3_L_FALSE:
    /* proved */
    if (!is_valid) {
      exit(0);
    }
    break;
  case Z3_L_UNDEF:
    m = Z3_solver_get_model(ctx, s);
    if (m != 0) {
      Z3_model_inc_ref(ctx, m);
    }
    if (is_valid) {
      exit(0);
    }
    break;
  case Z3_L_TRUE:
    /* disproved */
    m = Z3_solver_get_model(ctx, s);
    if (m) {
      Z3_model_inc_ref(ctx, m);
      /* the model returned by Z3 is a counterexample */
    }
    if (is_valid) {
      exit(0);
    }
    break;
  }
  if (m) {
    Z3_model_dec_ref(ctx, m);
  }

  /* restore scope */
  Z3_solver_pop(ctx, s, 1);
}

static void rop_gadget_info_constraint_find(
    RzCore *core, const RzRopConstraint *rop_constraint,
    RzRopGadgetInfo *gadget_info, const RopSolverCallbackParams *params) {
  rz_return_if_fail(params && params->constraints);
  if (is_rop_solver_complete(params->result)) {
    return;
  }
  switch (rop_constraint->type) {
  case MOV_CONST:
    return mov_const(core, gadget_info, rop_constraint, params);
  case MOV_REG:
    return mov_reg(core, gadget_info, rop_constraint, params);
  default:
    break;
  }
}

static bool rop_solver_cb(void *user, const ut64 k, const void *v) {
  const RopSolverCallbackParams *params = (RopSolverCallbackParams *)user;
  RzCore *core = params->core;
  const RzPVector *constraints = params->constraints;
  RzRopGadgetInfo *gadget_info = (RzRopGadgetInfo *)v;
  // If rop solver is complete, bail out from here
  if (is_rop_solver_complete(params->result)) {
    return false;
  }
  if (!core || !params->constraints) {
    return false;
  }
  void **it;
  rz_pvector_foreach(constraints, it) {
    const RzRopConstraint *rop_constraint = *it;
    rop_gadget_info_constraint_find(core, rop_constraint, gadget_info, params);
  }

  return true;
}

static RzRopSolverResult *
setup_rop_solver_result(const RzPVector /*<RzRopConstraint *>*/ *constraints) {
  rz_return_val_if_fail(constraints, NULL);
  RzRopSolverResult *result = rz_rop_solver_result_new();
  HtPUOptions opt = {0};
  result->constraint_result = ht_pu_new_opt(&opt);
  void **it;
  rz_pvector_foreach(constraints, it) {
    const RzRopConstraint *rop_constraint = *it;
    ht_pu_insert(result->constraint_result, rop_constraint, 0);
  }

  return result;
}

RZ_API RzRopSolverResult *
rz_rop_solver(const RzCore *core,
              RzPVector /*<RzRopConstraint *>*/ *constraints) {
  rz_return_val_if_fail(core && core->analysis, NULL);
  if (!core->analysis->ht_rop_semantics) {
    RZ_LOG_ERROR("ROP analysis not performed yet. Please run /Rg");
    return NULL;
  }
  RzRopSolverResult *result = setup_rop_solver_result(constraints);
  if (!result) {
    return NULL;
  }
  RopSolverCallbackParams params = {
      .core = core, .constraints = constraints, .result = result};

  ht_up_foreach(core->analysis->ht_rop_semantics, rop_solver_cb, &params);
  return result;
}

/**
 * \brief Creates a new RzRopSolverResult object.
 * \return A new RzRopSolverResult object.
 */
RZ_OWN RZ_API RzRopSolverResult *rz_rop_solver_result_new(void) {
  RzRopSolverResult *result = RZ_NEW0(RzRopSolverResult);
  if (!result) {
    return NULL;
  }

  result->is_solved = false;
  result->constraint_result = NULL;
  result->graph = NULL;
  result->gadget_info_addr_set = rz_pvector_new(NULL);
  result->rop_expressions = rz_pvector_new(NULL);
  result->ctx = rz_solver_mk_context();
  result->solver = rz_solver_mk_solver(result->ctx);
  return result;
}

/**
 * \brief Frees a RzRopSolverResult object.
 * \param result The RzRopSolverResult object to free.
 */
RZ_API void rz_rop_solver_result_free(RZ_NULLABLE RzRopSolverResult *result) {
  if (!result) {
    return;
  }
  ht_pu_free(result->constraint_result);
  rz_pvector_free(result->gadget_info_addr_set);
  rz_pvector_free(result->rop_expressions);
  RZ_FREE(result->graph);
  del_solver(result->ctx, result->solver);
  del_context(result->ctx);
  RZ_FREE(result);
}

/**
 * \brief Prints the result of the ROP solver.
 * \param result The RzRopSolverResult object to print.
 */
RZ_API void
rz_rop_solver_result_print(RZ_NULLABLE const RzRopSolverResult *result) {
  if (!result) {
    return;
  }
  void **it;
  rz_pvector_foreach(result->gadget_info_addr_set, it) {
    const ut64 addr = (ut64)*it;
    rz_cons_printf("ROP Gadget found at address: 0x%llx\n", addr);
  }
  rz_return_if_fail(result);
}
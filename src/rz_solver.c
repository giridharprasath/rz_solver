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
  const RzCore *core;
  const RzPVector *constraints;
  RzRopSolverResult *result;
} RopSolverCallbackParams;

// Struct for stack constraint query params
typedef struct {
  const RzCore *core;
  const RzRopConstraint *constraint;
  const ut64 val;
  const RzRopRegInfo *reg_info;
  const RzRopGadgetInfo *gadget_info;
} RopStackConstraintParams;

typedef struct {
  const RzCore *core;
  const RzRopConstraint *constraint;
  const RzRopGadgetInfo *gadget_info;
  RzRopSolverResult *result;
} RopSolverAnalysisOpParams;

static void update_rop_constraint_result(const RzRopSolverResult *result,
                                         const RzRopConstraint *constraint,
                                         const ut64 address) {
  rz_return_if_fail(result);
  rz_pvector_push(result->gadget_info_addr_set, (void *)address);
  if (!ht_pu_update(result->constraint_result, constraint, 1)) {
    rz_warn_if_reached();
  }
}

static ut64 parse_rop_constraint_int_val(const RzRopConstraint *rop_constraint,
                                         const RzRopArgType type) {
  if (!rop_constraint) {
    return -1;
  }
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

static inline bool is_leaf_op(const RzAnalysisOp *op) {
  return (op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_ILL ||
         (op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_RET ||
         (op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_UNK;
}

static inline bool is_call(const RzAnalysisOp *op) {
  const _RzAnalysisOpType type = (op->type & RZ_ANALYSIS_OP_TYPE_MASK);
  return type == RZ_ANALYSIS_OP_TYPE_CALL ||
         type == RZ_ANALYSIS_OP_TYPE_UCALL ||
         type == RZ_ANALYSIS_OP_TYPE_RCALL ||
         type == RZ_ANALYSIS_OP_TYPE_ICALL ||
         type == RZ_ANALYSIS_OP_TYPE_IRCALL ||
         type == RZ_ANALYSIS_OP_TYPE_CCALL ||
         type == RZ_ANALYSIS_OP_TYPE_UCCALL;
}

static bool is_uncond_jump(const RzAnalysisOp *op) {
  return (op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_JMP &&
         !((op->type & RZ_ANALYSIS_OP_HINT_MASK) & RZ_ANALYSIS_OP_TYPE_COND);
}

static bool is_return(const RzAnalysisOp *op) {
  return (op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_RET;
}

static bool is_cond(const RzAnalysisOp *op) {
  return (op->type & RZ_ANALYSIS_OP_HINT_MASK) == RZ_ANALYSIS_OP_TYPE_COND;
}

static bool is_mov(const RzAnalysisOp *op) {
  const _RzAnalysisOpType type = (op->type & RZ_ANALYSIS_OP_TYPE_MASK);
  return type == RZ_ANALYSIS_OP_TYPE_MOV || type == RZ_ANALYSIS_OP_TYPE_CMOV;
}

static void handle_mov_reg_analysis(const RopSolverAnalysisOpParams *op_params,
                                    const void *v) {
  rz_return_if_fail(op_params && op_params->constraint &&
                    op_params->gadget_info && v);
  const RzAnalysisOp *op = (RzAnalysisOp *)v;
  const RzRopConstraint *constraint = op_params->constraint;
  const RzRopGadgetInfo *gadget_info = op_params->gadget_info;
}

static void
handle_mov_const_analysis(const RopSolverAnalysisOpParams *op_params,
                          const void *v) {
  rz_return_if_fail(op_params && op_params->constraint && op_params &&
                    op_params->result && v && op_params->core);
  const RzRopConstraint *constraint = op_params->constraint;
  if (!constraint) {
    return;
  }
  const char *dst_reg = constraint->args[DST_REG];
  if (!dst_reg) {
    return;
  }
  const ut64 src_const = parse_rop_constraint_int_val(constraint, SRC_CONST);
  const RzAnalysisOp *op = (RzAnalysisOp *)v;
  const RzAnalysisValue *dst_val = op->dst;
  if (!dst_val) {
    return;
  }

  RzRegItem *dst_val_reg = dst_val->reg;
  if (!dst_val_reg) {
    return;
  }
  const RzCore *core = op_params->core;
  if (dst_val_reg->size != core->analysis->bits &&
      dst_val_reg->size != core->analysis->bits / 2) {
    return;
  }

  RzRopSolverResult *result = op_params->result;
  const RzRopGadgetInfo *gadget_info = op_params->gadget_info;
  if (!gadget_info) {
    return;
  }
  RzRopRegInfo *reg_info =
      rz_core_rop_gadget_info_get_modified_register(gadget_info, dst_reg);
  if (op->type) {
  }
  return;
}

static bool analysis_op_cb(void *user, const ut64 key, const void *v) {
  const RopSolverAnalysisOpParams *op_params =
      (RopSolverAnalysisOpParams *)user;
  if (!op_params) {
    return false;
  }

  if (!op_params->result) {
    return false;
  }
  const RzRopConstraint *constraint = op_params->constraint;
  switch (constraint->type) {
  case MOV_CONST:
    handle_mov_const_analysis(op_params, v);
  case MOV_REG:
    handle_mov_reg_analysis(op_params, v);
    break;
  default:
    break;
  }
  return true;
}

static bool has_value_cb(void *user, const void *key, const ut64 value) {
  RzRopSolverResult *result = user;
  if (!value) {
    result->is_solved = false;
    return true; // Continue iteration rop solver is not complete
  }
  result->is_solved = true;
  return false;
}

static bool is_rop_solver_complete(const RzRopSolverResult *result) {
  rz_return_val_if_fail(result, false);
  ht_pu_foreach(result->constraint_result, has_value_cb, (void *)result);
  return result->is_solved;
}

static void mov_reg(const RzCore *core, const RzRopGadgetInfo *gadget_info,
                    const RzRopConstraint *rop_constraint,
                    const RopSolverCallbackParams *params) {
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
  if (is_rop_solver_complete(params->result)) {
    return;
  }
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
                             const RzRopGadgetInfo *gadget_info, char *dst) {
  if (!gadget_info) {
    return false;
  }

  if (rz_pvector_len(gadget_info->modified_registers) != 2) {
    return false;
  }

  RzRopRegInfo *reg_info;
  RzListIter *iter;
  rz_list_foreach(gadget_info->dependencies, iter, reg_info) {
    if (rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_SP) ||
        rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_BP)) {
      continue;
    }
    return false;
  }

  return true;
}

static void rz_solver_direct_lookup(const RzCore *core,
                                    const RzRopGadgetInfo *gadget_info,
                                    const RzRopConstraint *rop_constraint,
                                    const RzRopSolverResult *result) {
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
  const bool is_dir_lookup =
      is_direct_lookup(core, gadget_info, rop_constraint->args[DST_REG]);
  if (info->new_val == src_val && is_dir_lookup) {
    update_rop_constraint_result(result, rop_constraint, gadget_info->address);
    return;
  }

  // Strategy: Search whether we can change the value through stack regs
  const RopStackConstraintParams stack_params = {
      .core = core,
      .constraint = rop_constraint,
      .val = src_val,
      .reg_info = info,
      .gadget_info = gadget_info,
  };
  if (stack_constraint(&stack_params, result)) {
    return;
  }
  return;
}

static void mov_const(const RzCore *core, const RzRopGadgetInfo *gadget_info,
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
  const RopSolverAnalysisOpParams analysis_op_params = {
      .core = core,
      .constraint = rop_constraint,
      .gadget_info = gadget_info,
      .result = callback_params->result};

  ht_up_foreach(gadget_info->analysis_cache, analysis_op_cb,
                (void *)&analysis_op_params);

  // Recipe : Search for dependencies and create a z3 state
}

static void rop_gadget_info_constraint_find(
    const RzCore *core, const RzRopConstraint *rop_constraint,
    const RzRopGadgetInfo *gadget_info, const RopSolverCallbackParams *params) {
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

  return;
}

static bool rop_solver_cb(void *user, const ut64 k, const void *v) {
  const RopSolverCallbackParams *params = (RopSolverCallbackParams *)user;
  const RzCore *core = params->core;
  const RzPVector *constraints = params->constraints;
  const RzRopGadgetInfo *gadget_info = (RzRopGadgetInfo *)v;
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
  result->gadget_info_addr_set = rz_pvector_new(NULL);
  result->ctx = rz_solver_mk_context();
  result->solver = rz_solver_mk_solver(result->ctx);
  return result;
}

/**
 * \brief Frees a RzRopSolverResult object.
 * \param result The RzRopSolverResult object to free.
 */
RZ_API void rz_rop_solver_result_free(RzRopSolverResult *result) {
  rz_return_if_fail(result);
  ht_pu_free(result->constraint_result);
  rz_pvector_free(result->gadget_info_addr_set);
  del_solver(result->ctx, result->solver);
  del_context(result->ctx);
  RZ_FREE(result);
}

/**
 * \brief Prints the result of the ROP solver.
 * \param result The RzRopSolverResult object to print.
 */
RZ_API void rz_rop_solver_result_print(const RzRopSolverResult *result) {
  void **it;
  rz_pvector_foreach(result->gadget_info_addr_set, it) {
    const ut64 addr = (ut64)*it;
    rz_cons_printf("ROP Gadget found at address: 0x%llx\n", addr);
  }
  rz_return_if_fail(result);
}
#include <z3.h>
#include <rz_core.h>
#include <rz_rop.h>
#include "rz_solver.h"
#include "rz_solver_util.h"

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

static void update_rop_constraint_result(const RzRopSolverResult *result, const RzRopConstraint *constraint, ut64 address) {
    rz_return_if_fail(result);
    rz_pvector_push(result->gadget_info_addr_set, (void *)address);
    ht_pu_insert(result->constraint_result, constraint, 1);
}

static bool has_value(void *user, const void *key, const ut64 value) {
    RzRopSolverResult *result = user;
    if (!value) {
        result->is_solved = false;
        return false;
    }
    result->is_solved = true;
    return true; // Continue iteration otherwise
}

static bool is_rop_solver_complete(const RzRopSolverResult *result) {
    rz_return_val_if_fail(result, false);
    ht_pu_foreach(result->constraint_result, has_value, (void *)result);
    return result->is_solved;
}

static ut64 parse_rop_constraint_int_val(const RzRopConstraint *rop_constraint) {
    const char *src_const = rop_constraint->args[SRC_CONST];
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

static void mov_reg(const RzCore *core, const RzRopGadgetInfo *gadget_info,
                    const RzRopConstraint *rop_constraint, const RopSolverCallbackParams *params) {
    // Assertions for mov_reg solver
    rz_return_if_fail(gadget_info && rop_constraint && rop_constraint->args);
    rz_return_if_fail(rop_constraint->args[SRC_REG] &&  rop_constraint->args[DST_REG]);
    rz_return_if_fail(core && core->analysis && core->analysis->reg);

    RzRopRegInfo *info = rz_core_rop_gadget_info_get_modified_register(gadget_info, rop_constraint->args[DST_REG]);
    if (!info) {
        return;
    }
    if (is_rop_solver_complete(params->result)) {
        return;
    }
    return;
}

static void stack_constraint(const RopStackConstraintParams *params) {
    const RzCore *core = params->core;
    rz_return_if_fail(core && core->analysis && core->analysis->reg);
    const char *sp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
    if (!sp) {
        return;
    }
    RzPVector /*<char *>*/ *query = rz_pvector_new(NULL);
    rz_pvector_push(query, (void *)sp);
    //RzPVector stack_query = rz_core_rop_get_reg_info_by_reg_names(params->gadget_info, query);

}

static void mov_const(const RzCore *core, const RzRopGadgetInfo *gadget_info,
                      const RzRopConstraint *rop_constraint, const RopSolverCallbackParams *params) {
    // Assertions for mov_const solver
    rz_return_if_fail(gadget_info && rop_constraint && rop_constraint->args);
    rz_return_if_fail(rop_constraint->args[SRC_CONST] && rop_constraint->args[DST_REG]);
    rz_return_if_fail(core && core->analysis && core->analysis->reg);
    if (is_rop_solver_complete(params->result)) {
        return;
    }

    RzRopRegInfo *info = rz_core_rop_gadget_info_get_modified_register(gadget_info, rop_constraint->args[DST_REG]);
    if (!info) {
        return;
    }

    // Direct lookup case
    const ut64 src_val = parse_rop_constraint_int_val(rop_constraint);
    if (src_val == -1) {
        return;
    }
    if (info->new_val == src_val) {
        update_rop_constraint_result(params->result, rop_constraint, gadget_info->address);
        return;
    }

    // Strategy: Search whether we can change the value through stack regs
    const RopStackConstraintParams stack_params = {
        .core = core,
        .constraint = rop_constraint,
        .val = src_val,
        .reg_info = info,
        .gadget_info = gadget_info
    };
    stack_constraint(&stack_params);

    // Recipe : Search for dependencies and create a z3 state

    const Z3_context ctx = mk_context();
    Z3_solver s = mk_solver(ctx);
    Z3_sort bv_sort = Z3_mk_bv_sort(ctx, 64);
    Z3_ast dst_val_ast = Z3_mk_numeral(ctx, rop_constraint->args[SRC_CONST], bv_sort);
    Z3_ast src_val_ast = Z3_mk_numeral(ctx, rz_str_newf("%llu", info->new_val), bv_sort);
    Z3_ast eq = Z3_mk_eq(ctx, dst_val_ast, src_val_ast);
    Z3_solver_assert(ctx, s, eq);
    if (Z3_solver_check(ctx, s) == Z3_L_TRUE) {
        display_ast(ctx, eq);
        return;
    }

    return;
}

static void rop_gadget_info_constraint_find(const RzCore *core, const RzRopConstraint *rop_constraint,
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
    if (is_rop_solver_complete(params->result)) {
        return false;
    }
    if (!core || !params->constraints) {
        return false;
    }
    void **it;
    rz_pvector_foreach (constraints, it) {
        const RzRopConstraint *rop_constraint = *it;
        rop_gadget_info_constraint_find(core, rop_constraint, gadget_info, params);
    }

    return true;
}

static RzRopSolverResult *setup_rop_solver_result(const RzPVector *constraints) {
    rz_return_val_if_fail(constraints, NULL);
    RzRopSolverResult *result = RZ_NEW0(RzRopSolverResult);
    HtPUOptions opt = { 0 };
    result->constraint_result = ht_pu_new_opt(&opt);
    void **it;
    rz_pvector_foreach (constraints, it) {
        const RzRopConstraint *rop_constraint = *it;
        ht_pu_insert(result->constraint_result, rop_constraint, 0);
    }

    return result;
}

RZ_API RzCmdStatus rz_rop_solver(const RzCore *core, RzPVector /*<RzRopConstraint *>*/ *constraints) {
    rz_return_val_if_fail(core && core->analysis, RZ_CMD_STATUS_ERROR);
    if (!core->analysis->ht_rop_semantics) {
        RZ_LOG_ERROR("ROP analysis not performed yet. Please run /Rg");
        return RZ_CMD_STATUS_ERROR;
    }
    RzRopSolverResult *result = setup_rop_solver_result(constraints);
    if (!result) {
        return RZ_CMD_STATUS_ERROR;
    }
    RopSolverCallbackParams params = {
        .core = core,
        .constraints = constraints,
        .result = result
    };

    ht_up_foreach(core->analysis->ht_rop_semantics, rop_solver_cb, &params);
    rz_rop_solver_result_print(result);

    rz_rop_solver_result_free(result);
    return RZ_CMD_STATUS_OK;
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
    RZ_FREE(result);
}

/**
 * \brief Prints the result of the ROP solver.
 * \param result The RzRopSolverResult object to print.
 */
RZ_API void rz_rop_solver_result_print(const RzRopSolverResult *result) {
    rz_return_if_fail(result);

}
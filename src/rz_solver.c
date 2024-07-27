#include <z3.h>
#include <rz_core.h>
#include <rz_rop.h>
#include <rz_solver.h>

static bool mov_reg(const RzRopGadgetInfo *gadget_info, const RzRopConstraint *rop_constraint) {
    RzRopRegInfo *info = rz_core_rop_gadget_info_get_modified_register(gadget_info, rop_constraint->args[SRC_REG]);
    if (!info) {
        return false;
    }
    return true;
}

static bool mov_const(const RzRopGadgetInfo *gadget_info, const RzRopConstraint *rop_constraint) {
    rz_cons_println(rop_constraint->args[DST_REG]);
    RzRopRegInfo *info = rz_core_rop_gadget_info_get_modified_register(gadget_info, rop_constraint->args[DST_REG]);
    if (!info) {
        return false;
    }

    RZ_LOG_ERROR("%s", info->name);
    return true;
}

static bool rop_gadget_info_constraint_find(const RzRopGadgetInfo *gadget_info, const RzRopConstraint *rop_constraint) {
    switch (rop_constraint->type) {
        case MOV_CONST:
            return mov_const(gadget_info, rop_constraint);
        case MOV_REG:
            return mov_reg(gadget_info, rop_constraint);
        default:
            break;
    }

    return false;
}

static bool rop_solver_cb(void *user, const ut64 k, const void *v) {
    const RzList /*<RzRopConstraint *>*/ *constraints = user;
    const RzRopGadgetInfo *gadget_info = (RzRopGadgetInfo *)v;

    // Direct lookup case
    RzListIter *it;
    RzRopConstraint *rop_constraint;
    rz_list_foreach (constraints, it, rop_constraint) {
        rop_gadget_info_constraint_find(gadget_info, rop_constraint);
    }

    return true;
}

RZ_API RzCmdStatus rz_rop_solver(const RzCore *core, RzList /*<RzRopConstraint *>*/ *constraints) {
    rz_return_val_if_fail(core && core->analysis, RZ_CMD_STATUS_ERROR);
    if (!core->analysis->ht_rop_semantics) {
        RZ_LOG_ERROR("ROP analysis not performed yet. Please run /Rg");
        return RZ_CMD_STATUS_ERROR;
    }

    ht_up_foreach(core->analysis->ht_rop_semantics, rop_solver_cb, constraints);
    return RZ_CMD_STATUS_OK;
}
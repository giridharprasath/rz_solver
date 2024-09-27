#include "minunit.h"
#include "rz_solver.h"
#include <rz_core.h>
#include <rz_rop.h>

// Only one gadget is added once for each test case.
#define ROP_GADGET_MAX_SIZE 16

static const char *x86_64_buf_str[] = {
    // mov rbx, 1; ret;
    "48C7C301000000C3",
    // mov rbx, rax; ret;
    "89c3c3"};

static const char *x86_64_constraints_str[] = {
    "rbx=1",
    "rbx=rax",
};

static RzCoreAsmHit *setup_rop_hitasm(int addr, int len) {
  RzCoreAsmHit *hit = rz_core_asm_hit_new();
  if (!hit) {
    return NULL;
  }
  hit->addr = addr;
  hit->len = len;
  return hit;
}

static RzList /*<RzCoreAsmHit *>*/ *
setup_rop_hitlist(RzCore *core, ut8 *buf_str, int addr, int len) {
  RzAnalysisOp aop = {0};
  rz_analysis_op_init(&aop);
  if (rz_analysis_op(core->analysis, &aop, addr + len - 1, buf_str + len - 1, 1,
                     RZ_ANALYSIS_OP_MASK_DISASM) < 0) {
    return NULL;
  }

  if (aop.type != RZ_ANALYSIS_OP_TYPE_RET) {
    return NULL;
  }

  RzList /*<RzCoreAsmHit *>*/ *hitlist = rz_list_newf(rz_core_asm_hit_free);
  if (!hitlist) {
    return NULL;
  }

  RzCoreAsmHit *hit = setup_rop_hitasm(addr, len - 1);
  if (!hit) {
    rz_list_free(hitlist);
    return NULL;
  }
  rz_list_append(hitlist, hit);
  hit = setup_rop_hitasm(addr + len - 1, 1);
  if (!hit) {
    rz_list_free(hitlist);
    return NULL;
  }
  rz_list_append(hitlist, hit);
  return hitlist;
}

static RzCore *setup_rz_core(char *arch, int bits) {
  RzCore *core = rz_core_new();
  if (!core) {
    return NULL;
  }
  rz_io_open_at(core->io, "malloc://0x100", RZ_PERM_RX, 0644, 0, NULL);
  rz_core_set_asm_configs(core, arch, bits, 0);
  rz_config_set_b(core->config, "asm.lines", false);
  return core;
}

static RzPVector *setup_rop_constraints(RzCore *core) {
  RzPVector *constraints = rz_core_rop_constraint_new();
  if (!constraints) {
    return NULL;
  }
  int size = sizeof(x86_64_constraints_str) / sizeof(x86_64_constraints_str[0]);
  for (int i = 0; i < size; i++) {
    RzRopConstraint *rop_constraint =
        rop_constraint_parse_args(core, x86_64_constraints_str[i]);
    if (!rop_constraint) {
      rz_pvector_fini(constraints);
      return NULL;
    }
    rz_pvector_push(constraints, rop_constraint);
  }
  return constraints;
}

static void cleanup_test(RzCore *core, RzPVector *constraints,
                         RzRopSolverResult *result) {
  rz_pvector_fini(constraints);
  rz_rop_solver_result_free(result);
  rz_core_free(core);
}

bool test_rz_direct_solver() {
  RzCore *core = setup_rz_core("x86", 64);
  mu_assert_notnull(core, "setup_rz_core failed");
  int size = sizeof(x86_64_buf_str) / sizeof(x86_64_buf_str[0]);
  int addr = 0;
  RzRopSearchContext *context = rz_core_rop_search_context_new(
      core, NULL, false, RZ_ROP_GADGET_PRINT_DETAIL | RZ_ROP_GADGET_ANALYZE,
      NULL);
  mu_assert_notnull(context, "rz_core_rop_search_context_new failed");
  for (int i = 0; i < size; i++) {
    ut8 buf[ROP_GADGET_MAX_SIZE] = {0};
    int len = rz_hex_str2bin(x86_64_buf_str[i], buf);
    rz_io_write_at(core->io, addr, buf, len);
    RzList /*<RzCoreAsmHit *>*/ *hitlist =
        setup_rop_hitlist(core, buf, addr, len);
    mu_assert_notnull(hitlist, "setup_rop_hitlist failed");
    rz_core_handle_rop_request_type(core, context, hitlist);
    addr += len + 1;
    rz_list_free(hitlist);
  }

  RzPVector *constraints = setup_rop_constraints(core);
  mu_assert_notnull(constraints, "rop_constraint_parse_args failed");
  RzRopSolverResult *result = rz_rop_solver(core, constraints);
  mu_assert_true(result->is_solved, "rz_rop_solver failed");
  cleanup_test(core, constraints, result);
  mu_end;
}

bool all_tests() {
  mu_run_test(test_rz_direct_solver);
  return tests_passed != tests_run;
}

mu_main(all_tests)

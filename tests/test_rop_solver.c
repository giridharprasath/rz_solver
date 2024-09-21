#include "minunit.h"
#include "rz_solver.h"
#include <rz_core.h>
#include <rz_rop.h>

static RzCoreAsmHit *setup_rop_hitasm(int addr, int len) {
  RzCoreAsmHit *hit = rz_core_asm_hit_new();
  if (!hit) {
    return NULL;
  }
  hit->addr = addr;
  hit->len = len;
  return hit;
}

static RzList *setup_rop_hitlist(RzCore *core, ut8 *buf_str, int addr,
                                 int len) {
  RzAnalysisOp aop = {0};
  rz_analysis_op_init(&aop);
  if (rz_analysis_op(core->analysis, &aop, addr + len - 1, buf_str + len - 1, 1,
                     RZ_ANALYSIS_OP_MASK_DISASM) < 0) {
    return NULL;
  }
  if (aop.type != RZ_ANALYSIS_OP_TYPE_RET) {
    return NULL;
  }
  RzList *hitlist = rz_list_newf(rz_core_asm_hit_free);
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

bool test_rz_direct_solver() {
  // mov rbx, 1; ret;
  ut8 buf_str[] = "48C7C301000000C3";

  RzCore *core = rz_core_new();
  rz_io_open_at(core->io, "malloc://0x100", RZ_PERM_RX, 0644, 0, NULL);
  rz_core_set_asm_configs(core, "x86", 64, 0);
  rz_config_set_b(core->config, "asm.lines", false);
  ut8 buf[128] = {0};
  int len = rz_hex_str2bin(buf_str, buf);
  RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_analysis_disasm_text_free);
  mu_assert_notnull(vec, "rz_core_print_disasm vec not null");
  int addr = 0;
  rz_io_write_at(core->io, addr, buf, len);
  RzList /*<RzCoreAsmHit *>*/ *hitlist =
      setup_rop_hitlist(core, buf, addr, len);
  if (!hitlist) {
    return NULL;
  }
  RzRopSearchContext *context = rz_core_rop_search_context_new(
      core, NULL, false, RZ_ROP_GADGET_PRINT_DETAIL | RZ_ROP_GADGET_ANALYZE,
      NULL);
  rz_core_handle_rop_request_type(core, context, hitlist);
  RzPVector *constraints = rz_core_rop_constraint_map_new();
  RzRopConstraint *rop_constraint = rop_constraint_parse_args(core, "rbx=1");
  rz_pvector_push(constraints, rop_constraint);
  mu_assert_notnull(rop_constraint, "rop_constraint_parse_args failed");
  RzRopSolverResult *result = rz_rop_solver(core, constraints);
  mu_assert_true(result->is_solved, "rz_rop_solver failed");
  rz_pvector_fini(constraints);
  mu_end;
}

bool all_tests() {
  mu_run_test(test_rz_direct_solver);
  return tests_passed != tests_run;
}

mu_main(all_tests)

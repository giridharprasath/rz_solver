#include <rz_core.h>

#define SWITCH_TO_ARCH_BITS(arch, bits) \
	rz_analysis_use(analysis, arch); \
	rz_analysis_set_bits(analysis, bits);


int main() {
    RzAnalysis *analysis = rz_analysis_new();
    RzAnalysisOp op;
    SWITCH_TO_ARCH_BITS("x86", 64);
    // mov rax, 4
    rz_analysis_op_init(&op);

    int len = rz_analysis_op(analysis, &op, 0, (const ut8 *)"\x48\xC7\xC0\x04\x00\x00\x00", 7, RZ_ANALYSIS_OP_MASK_VAL);
}

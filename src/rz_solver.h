#ifndef RZ_SOLVER_LIBRARY_H
#define RZ_SOLVER_LIBRARY_H

#include <rz_core.h>
#include <rz_rop.h>
#include <rz_cmd.h>

RZ_API RzCmdStatus rz_rop_solver(const RzCore *core, RzList /*<RzRopConstraint *>*/ *constraints);

#endif //RZ_SOLVER_LIBRARY_H

// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: MIT

/**
 * \file rz_solver_plugin.c
 * Adds core plugin to Rizin
 */

#include <rz_rop.h>

#include "rz_solver.h"

static const RzCmdDescArg cmd_rop_solver_args[] = {
    {.name = "Gadget constraints",
     .type = RZ_CMD_ARG_TYPE_STRING,
     .flags = RZ_CMD_ARG_FLAG_LAST,
     .optional = false

    },
    {0},
};

static const RzCmdDescHelp cmd_rop_solver_help = {
    .summary = "ROP Gadget solver help",
    .args = cmd_rop_solver_args,
};

/**
 * \brief Handler for the rop solver command
 * \param core Rizin core
 * \param argc Number of arguments
 * \param argv Arguments
 * \param state Output state
 * \return RZ_CMD_STATUS_ERROR if constraints are not parsed,
 * RZ_CMD_STATUS_INVALID if constraints are empty, RZ_CMD_STATUS_OK otherwise
 */
RZ_IPI RzCmdStatus rz_cmd_rop_solver_handler(RzCore *core, int argc,
                                             const char **argv,
                                             RzCmdStateOutput *state) {
  RzPVector /*<RzRopConstraint *>*/ *constraints =
      rop_constraint_map_parse(core, argc, argv);
  if (!constraints) {
    return RZ_CMD_STATUS_ERROR;
  }
  if (rz_pvector_empty(constraints)) {
    rz_pvector_fini(constraints);
    return RZ_CMD_STATUS_INVALID;
  }
  RzRopSolverResult *result = rz_rop_solver(core, constraints);
  rz_rop_solver_result_print(result);

  rz_rop_solver_result_free(result);

  return RZ_CMD_STATUS_OK;
}

/**
 * \brief Initializes the plugin
 * \param core Rizin core
 * \return true if the plugin is initialized successfully, false otherwise
 */
RZ_IPI bool solver_plugin_init(RzCore *core) {
  RzCmd *rcmd = core->rcmd;
  RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
  if (!root_cd) {
    rz_warn_if_reached();
    return false;
  }

  RzCmdDesc *root_cmd = rz_cmd_get_desc(rcmd, "/R");

  RzCmdDesc *cmd_rop_solver_cd = rz_cmd_desc_argv_state_new(
      core->rcmd, root_cmd, "/Rs", RZ_OUTPUT_MODE_STANDARD,
      rz_cmd_rop_solver_handler, &cmd_rop_solver_help);
  rz_warn_if_fail(cmd_rop_solver_cd);
  rz_cmd_desc_set_default_mode(cmd_rop_solver_cd, RZ_OUTPUT_MODE_STANDARD);

  return true;
}

/**
 * \brief Plugin Cleanup
 * \param core Rizin core
 * \return true if the plugin is finalized successfully, false otherwise
 */
RZ_IPI bool solver_plugin_fini(RzCore *core) {
  RzCmd *cmd = core->rcmd;
  RzCmdDesc *desc = rz_cmd_get_desc(cmd, "/Rs");
  return rz_cmd_desc_remove(cmd, desc);
}

RzCorePlugin rz_core_plugin_solver = {
    .name = "rz_solver",
    .author = "z3phyr",
    .desc = "Rizin Solver",
    .license = "MIT",
    .init = solver_plugin_init,
    .fini = solver_plugin_fini,
};

#ifdef _MSC_VER
#define RZ_EXPORT __declspec(dllexport)
#else
#define RZ_EXPORT
#endif

#ifndef CORELIB
RZ_EXPORT RzLibStruct rizin_plugin = {
    .type = RZ_LIB_TYPE_CORE,
    .data = &rz_core_plugin_solver,
    .version = RZ_VERSION,
};
#endif

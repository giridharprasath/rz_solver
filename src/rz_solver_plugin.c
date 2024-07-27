// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file rz_solver_plugin.c
 * Adds core plugin to integr
 */

#include "rz_solver.h"

static const RzCmdDescArg cmd_rop_solver_args[] = {
	{
		.name = "Gadget constraints",
		.type = RZ_CMD_ARG_TYPE_STRING,
		.flags = RZ_CMD_ARG_FLAG_LAST,
		.optional = false

	},
	{ 0 },
};

static const RzCmdDescHelp cmd_rop_solver_help = {
	.summary = "ROP Gadget solver help",
	.args = cmd_rop_solver_args,
};

RZ_IPI RzCmdStatus rz_cmd_rop_solver_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *input = argc > 1 ? argv[1] : "";
	return RZ_CMD_STATUS_OK;
}

RZ_IPI bool solver_plugin_init(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		rz_warn_if_reached();
		return false;
	}

	RzCmdDesc* root_cmd = rz_cmd_get_desc(rcmd, "/R");

	RzCmdDesc *cmd_rop_solver_cd = rz_cmd_desc_argv_state_new(core->rcmd, root_cmd, "/Rs", RZ_OUTPUT_MODE_STANDARD, rz_cmd_rop_solver_handler, &cmd_rop_solver_help);
	rz_warn_if_fail(cmd_rop_solver_cd);
	rz_cmd_desc_set_default_mode(cmd_rop_solver_cd, RZ_OUTPUT_MODE_STANDARD);

	return true;
}

RZ_IPI bool solver_plugin_fini(RzCore *core) {
	RzCmd *cmd = core->rcmd;
	RzCmdDesc *desc = rz_cmd_get_desc(cmd, "solver");
	return rz_cmd_desc_remove(cmd, desc);
}

RzCorePlugin rz_core_plugin_solver = {
	.name = "rz_solver",
	.author = "z3phyr",
	.desc = "Rizin Solver",
	.license = "MIT",
	.init = solver_plugin_init,
	.fini = solver_plugin_fini,
	//.analysis = solver_plugin_analysis,
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

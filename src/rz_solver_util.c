// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: MIT

#include "rz_solver_util.h"

/**
 * \brief Create a variable with a given name and type.
 * \param ctx Z3 context
 * \param name Name of the variable
 * \param type Type of the variable
 * \return Z3_ast
 */
RZ_API Z3_ast mk_var(const Z3_context ctx, const char *name,
                     const Z3_sort type) {
  const Z3_symbol s = Z3_mk_string_symbol(ctx, name);
  return Z3_mk_const(ctx, s, type);
}

/**
 * \brie/home/z3phyr/personal/rizin-dev/rizinf Create a boolean variable with a given name.
 * \param ctx Z3 context
 * \param name Name of the variable
 * \return Z3_ast
 */
RZ_API Z3_ast mk_bool_var(const Z3_context ctx, const char *name) {
  const Z3_sort ty = Z3_mk_bool_sort(ctx);
  return mk_var(ctx, name, ty);
}

/**
 * \brief Create an integer variable with a given name.
 * \param ctx Z3 context
 * \param name Name of the variable
 * \return Z3_ast
 */
RZ_API Z3_ast mk_int_var(const Z3_context ctx, const char *name) {
  const Z3_sort ty = Z3_mk_int_sort(ctx);
  return mk_var(ctx, name, ty);
}

/**
 * \brief Create an integer constant with a given value.
 * \param ctx Z3 context
 * \param value Integer value
 * \return Z3_ast
 */
RZ_API Z3_ast mk_int(const Z3_context ctx, const int value) {
  const Z3_sort ty = Z3_mk_int_sort(ctx);
  return Z3_mk_int(ctx, value, ty);
}

/**
 * \brief Create a real variable with a given name.
 * \param ctx Z3 context
 * \param name Name of the variable
 * \return Z3_ast
 */
RZ_API Z3_ast mk_real_var(const Z3_context ctx, const char *name) {
  const Z3_sort ty = Z3_mk_real_sort(ctx);
  return mk_var(ctx, name, ty);
}

/**
 * \brief Create a real constant with a given value.
 * \param ctx Z3 context
 * \param func Z3 function declaration
 * \param ast Z3 ast
 * \return Z3_ast
 */
RZ_API Z3_ast mk_unary_app(const Z3_context ctx, const Z3_func_decl func,
                           const Z3_ast ast) {
  const Z3_ast args[1] = {ast};
  return Z3_mk_app(ctx, func, 1, args);
}

/**
 * \brief Create a binary application.
 * \param ctx Z3 context
 * \param func Z3 function declaration
 * \param ast_left Z3 ast
 * \param ast_right Z3 ast
 * \return Z3_ast
 */
RZ_API Z3_ast mk_binary_app(const Z3_context ctx, const Z3_func_decl func,
                            const Z3_ast ast_left, const Z3_ast ast_right) {
  const Z3_ast args[2] = {ast_left, ast_right};
  return Z3_mk_app(ctx, func, 2, args);
}

/**
 * \brief Create a solver.
 * \param ctx Z3 context
 * \return Z3_solver
 */
RZ_API Z3_solver rz_solver_mk_solver(const Z3_context ctx) {
  const Z3_solver s = Z3_mk_solver(ctx);
  Z3_solver_inc_ref(ctx, s);
  return s;
}

static void display_symbol(const Z3_context c, const Z3_symbol s) {
  switch (Z3_get_symbol_kind(c, s)) {
  case Z3_INT_SYMBOL:
    rz_cons_printf("#%d", Z3_get_symbol_int(c, s));
    break;
  case Z3_STRING_SYMBOL:
    rz_cons_printf("%s", Z3_get_symbol_string(c, s));
    break;
  default:
    break;
  }
}

static void display_sort(const Z3_context c, const Z3_sort ty) {
  switch (Z3_get_sort_kind(c, ty)) {
  case Z3_UNINTERPRETED_SORT:
    display_symbol(c, Z3_get_sort_name(c, ty));
    break;
  case Z3_BOOL_SORT:
    rz_cons_printf("bool");
    break;
  case Z3_INT_SORT:
    rz_cons_printf("int");
    break;
  case Z3_REAL_SORT:
    rz_cons_printf("real");
    break;
  case Z3_BV_SORT:
    rz_cons_printf("bv%d", Z3_get_bv_sort_size(c, ty));
    break;
  case Z3_ARRAY_SORT:
    rz_cons_printf("[");
    display_sort(c, Z3_get_array_sort_domain(c, ty));
    rz_cons_printf("->");
    display_sort(c, Z3_get_array_sort_range(c, ty));
    rz_cons_printf("]");
    break;
  case Z3_DATATYPE_SORT:
    if (Z3_get_datatype_sort_num_constructors(c, ty) != 1) {
      rz_cons_printf("%s", Z3_sort_to_string(c, ty));
      break;
    }
    {
      const unsigned num_fields = Z3_get_tuple_sort_num_fields(c, ty);
      rz_cons_printf("(");
      for (int i = 0; i < num_fields; i++) {
        const Z3_func_decl field = Z3_get_tuple_sort_field_decl(c, ty, i);
        if (i > 0) {
          rz_cons_printf(", ");
        }
        display_sort(c, Z3_get_range(c, field));
      }
      rz_cons_printf(")");
      break;
    }
  default:
    rz_cons_printf("unknown[");
    display_symbol(c, Z3_get_sort_name(c, ty));
    rz_cons_printf("]");
    break;
  }
}

/**
 * \brief Display an AST
 * \param ctx Z3 context
 * \param ast Z3 ast
 * \return void
 */
RZ_API void display_ast(const Z3_context ctx, const Z3_ast ast) {
  switch (Z3_get_ast_kind(ctx, ast)) {
  case Z3_NUMERAL_AST: {
    rz_cons_printf("%s", Z3_get_numeral_string(ctx, ast));
    const Z3_sort t = Z3_get_sort(ctx, ast);
    rz_cons_printf(":");
    display_sort(ctx, t);
    break;
  }
  case Z3_APP_AST: {
    const Z3_app app = Z3_to_app(ctx, ast);
    const unsigned num_fields = Z3_get_app_num_args(ctx, app);
    const Z3_func_decl d = Z3_get_app_decl(ctx, app);
    rz_cons_printf("%s", Z3_func_decl_to_string(ctx, d));
    if (num_fields > 0) {
      rz_cons_printf("[");
      for (int i = 0; i < num_fields; i++) {
        if (i > 0) {
          rz_cons_printf(", ");
        }
        display_ast(ctx, Z3_get_app_arg(ctx, app, i));
      }
      rz_cons_printf("]");
    }
    break;
  }
  case Z3_QUANTIFIER_AST: {
    rz_cons_printf("quantifier");
    break;
  }
  default:
    rz_cons_printf("#unknown");
  }
}

static void display_function_interpretations(const Z3_context ctx,
                                             const Z3_model model) {
  rz_cons_printf("function interpretations:\n");

  const ut64 num_functions = Z3_model_get_num_funcs(ctx, model);
  for (ut64 i = 0; i < num_functions; i++) {
    unsigned num_entries = 0, j;

    const Z3_func_decl fdecl = Z3_model_get_func_decl(ctx, model, i);
    const Z3_func_interp_opt finterp =
        Z3_model_get_func_interp(ctx, model, fdecl);
    Z3_func_interp_inc_ref(ctx, finterp);
    const Z3_symbol name = Z3_get_decl_name(ctx, fdecl);
    display_symbol(ctx, name);
    rz_cons_printf(" = {");
    if (finterp)
      num_entries = Z3_func_interp_get_num_entries(ctx, finterp);
    for (j = 0; j < num_entries; j++) {
      const Z3_func_entry fentry = Z3_func_interp_get_entry(ctx, finterp, j);
      Z3_func_entry_inc_ref(ctx, fentry);
      if (j > 0) {
        rz_cons_printf(", ");
      }
      unsigned num_args = Z3_func_entry_get_num_args(ctx, fentry);
      rz_cons_printf("(");
      for (int k = 0; k < num_args; k++) {
        if (k > 0) {
          rz_cons_printf(", ");
        }
        display_ast(ctx, Z3_func_entry_get_arg(ctx, fentry, k));
      }
      rz_cons_printf("|->");
      display_ast(ctx, Z3_func_entry_get_value(ctx, fentry));
      rz_cons_printf(")");
      Z3_func_entry_dec_ref(ctx, fentry);
    }
    if (num_entries > 0) {
      rz_cons_printf(", ");
    }
    rz_cons_printf("(else|->");
    const Z3_ast func_else = Z3_func_interp_get_else(ctx, finterp);
    display_ast(ctx, func_else);
    rz_cons_printf(")}\n");
    Z3_func_interp_dec_ref(ctx, finterp);
  }
}

/**
 * \brief Display a Z3 model
 * \param ctx Z3 context
 * \param model Z3 model
 * \return void
 */
RZ_API void display_model(const Z3_context ctx, const Z3_model model) {
  if (!model) {
    return;
  }

  const unsigned num_constants = Z3_model_get_num_consts(ctx, model);
  for (int i = 0; i < num_constants; i++) {
    const Z3_func_decl cnst = Z3_model_get_const_decl(ctx, model, i);
    Z3_ast v;
    const Z3_symbol name = Z3_get_decl_name(ctx, cnst);
    display_symbol(ctx, name);
    rz_cons_printf(" = ");
    const Z3_ast a = Z3_mk_app(ctx, cnst, 0, 0);
    v = a;
    Z3_model_eval(ctx, model, a, 1, &v);
    display_ast(ctx, v);
    rz_cons_printf("\n");
  }
  display_function_interpretations(ctx, model);
}

/**
 * \brief Check the result of a solver
 * \param ctx Z3 context
 * \param solver Z3 solver
 * \param expected_result Expected result
 * \return void
 */
RZ_API void check2(const Z3_context ctx, const Z3_solver solver,
                   const Z3_lbool expected_result) {
  Z3_model m = 0;
  const Z3_lbool result = Z3_solver_check(ctx, solver);
  switch (result) {
  case Z3_L_FALSE:
    rz_cons_printf("unsat\n");
    break;
  case Z3_L_UNDEF:
    rz_cons_printf("unknown\n");
    rz_cons_printf("potential model:\n");
    m = Z3_solver_get_model(ctx, solver);
    if (m) {
      Z3_model_inc_ref(ctx, m);
    }
    display_model(ctx, m);
    break;
  case Z3_L_TRUE:
    rz_cons_printf("sat\n");
    m = Z3_solver_get_model(ctx, solver);
    if (m) {
      Z3_model_inc_ref(ctx, m);
    }
    display_model(ctx, m);
    break;
  }
  if (result != expected_result) {
  }
  if (m) {
    Z3_model_dec_ref(ctx, m);
  }
}

/**
 * \brief Delete a solver
 * \param ctx Z3 context
 * \param solver Z3 solver
 * \return void
 */
RZ_API void del_solver(const Z3_context ctx, const Z3_solver solver) {
  rz_return_if_fail(ctx && solver);
  Z3_solver_dec_ref(ctx, solver);
}

/**
 * \brief Delete a context
 * \param ctx Z3 context
 * \return void
 */
RZ_API void del_context(const Z3_context ctx) {
  rz_return_if_fail(ctx);
  Z3_del_context(ctx);
}

static void error_handler(Z3_context c, Z3_error_code e) {
  rz_cons_printf("Error code: %d\n", e);
}

static Z3_context mk_context_custom(const Z3_config cfg,
                                    const Z3_error_handler err) {
  Z3_set_param_value(cfg, "model", "true");
  const Z3_context ctx = Z3_mk_context(cfg);
  if (!ctx) {
    return NULL;
  }
  Z3_set_error_handler(ctx, err);

  return ctx;
}

/**
 * \brief Create z3 context
 * \return Z3 context
 */
RZ_API Z3_context rz_solver_mk_context() {
  const Z3_config cfg = Z3_mk_config();
  if (!cfg) {
    return NULL;
  }
  const Z3_context ctx = mk_context_custom(cfg, error_handler);
  if (!ctx) {
    return NULL;
  }
  Z3_del_config(cfg);
  return ctx;
}

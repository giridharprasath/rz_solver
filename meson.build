project('rz_solver', 'c',
        meson_version: '>=0.55.0',
        version: '0.1',
)

cc = meson.get_compiler('c')
rz_core_dep = dependency('rz_core')

py3_exe = import('python').find_installation()
check_meson_subproject_py = files('sys/check_meson_subproject.py')
subproject_clean_error_msg = 'Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories.'

# handle z3 library
sys_z3_opt = get_option('use_sys_z3')
z3_dep = disabler()
if sys_z3_opt.enabled() or sys_z3_opt.auto()
    z3_dep = dependency('z3', required: false)
    if not z3_dep.found()
        z3_dep = cc.find_library('z3', required: sys_z3_opt)
    endif
endif
if (sys_z3_opt.auto() and not z3_dep.found()) or sys_z3_opt.disabled()
    z3_proj = subproject('z3', default_options: ['default_library=static'])
    z3_dep = z3_proj.get_variable('z3_dep')
endif

r = run_command(py3_exe, check_meson_subproject_py, 'z3', check: false)
if r.returncode() == 1
    error(subproject_clean_error_msg)
endif

rz_solver_deps = [
    rz_core_dep,
    #rz_rop_dep,
    z3_dep,
]

rz_solver_incs = ['.', 'src']

rz_solver_src = [
    'src'/'rz_solver.c',
    'src'/'rz_solver_util.c',
    'src'/'rz_solver_plugin.c',
]

rizin_plugdir = get_option('rizin_plugdir')
if rizin_plugdir == ''
    rizin_plugdir = rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
endif

rz_solver_lib = shared_library('rz_solver', rz_solver_src,
                                   c_args : [],
                                   dependencies: rz_solver_deps,
                                   implicit_include_directories: false,
                                   install: true,
                                   install_dir: rizin_plugdir,
                                   include_directories: include_directories(rz_solver_incs)
)

subdir('tests')
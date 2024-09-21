rz_solver_incs = include_directories(['.', '..', '../src'])

test_sources = [
    '../src'/'rz_solver.c',
    '../src'/'rz_solver_util.c',
    '../src'/'rz_solver_plugin.c',
    'test_rop_solver.c',
    # Add more test files as needed
]

test_exe = executable('test_solver', test_sources,
                      dependencies: rz_solver_deps,
                      include_directories: rz_solver_incs
)

test('rz_solver_tests', test_exe)
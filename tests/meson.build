rz_solver_incs = include_directories(['.', '..', '../src'])

test_sources = [
    'test_rop_solver.c',
    # Add more test files as needed
]

test_exe = executable('test_solver', test_sources,
                      dependencies: rz_solver_deps,
                      include_directories: rz_solver_incs
)

# Register the test without include_directories
test('rz_solver_tests', test_exe)
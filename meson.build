project('pam_ibmacf', 'cpp', default_options : ['cpp_std=c++17'])

cxx = meson.get_compiler('cpp')

#Link with subproject
sp = subproject('ce-login')
libcelogin_dep = sp.get_variable('lib_ce_login_dep')

#Dependencies
pam = cxx.find_library('pam', required: true)
libcrypto = dependency('libcrypto', required : true)
libssl = dependency('libssl', required : true)
sdbusplus = dependency('sdbusplus', version : '>=1.0.0', required : true, fallback : ['sdbusplus', 'sdbusplus_dep' ])
deps = [sdbusplus, libcrypto, libssl, libcelogin_dep, pam]
build_target('pam_ibmacf', 'pam_ibmacf.cpp', pic : true, name_prefix : '', target_type: 'shared_library', dependencies : deps, install : true, install_dir : '/lib/security')

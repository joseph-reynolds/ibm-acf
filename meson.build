project('pam_ibmacf', 'cpp', default_options : ['cpp_std=c++17'])

#Link with subproject
sp = subproject('ce-login')
libcelogin_dep = sp.get_variable('lib_ce_login_dep')

#Dependencies
linklibs = declare_dependency(
     link_args : ['-lpam' , '-ldl', '-lpthread' ]
      )
libcrypto = dependency('libcrypto', required : true)
libssl = dependency('libssl', required : true)
sdbusplus = dependency('sdbusplus', version : '>=1.0.0', required : true, fallback : ['sdbusplus', 'sdbusplus_dep' ])

build_target('pam_ibmacf', 'pam_ibmacf.cpp', cpp_args : '-fPIC' ,name_prefix : '', target_type: 'shared_library', dependencies : [sdbusplus, linklibs, libcrypto, libssl, libcelogin_dep], install : true, install_dir : '/lib/security')

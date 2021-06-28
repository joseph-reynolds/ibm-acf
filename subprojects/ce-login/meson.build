project('ce-login', 'cpp',
  version : '1.0.0')

libcrypto = dependency('libcrypto', required : true)
libssl = dependency('libssl', required : true)
ldl = declare_dependency( link_args : '-ldl' )
#Needed for cli
ljsonc = declare_dependency( link_args : '-ljson-c' )

deps = [ libcrypto, libssl, ldl, ljsonc  ]
args = ['-O2', '-DMFG_IBMI_TARGET']

#sources
ce_login_sources = ['celogin/src/CeLoginAsnV1.cpp',
                    'celogin/src/CeLogin.cpp',
                    'celogin/src/CeLoginJson.cpp',
                    'celogin/src/CeLoginJsonExterns.cpp',
                    'celogin/src/CeLoginUtil.cpp',
                    'celogin/src/JsmnUtils.cpp',
                    'celogin/src/Jsmn.cpp',
                    'celogin/src/CeLoginAsnV1.cpp',
                    ]

cli_sources = [ 'cli/CliCeLoginV1.cpp',
                'cli/CliCreateHsf.cpp',
                'cli/CliDecodeHsf.cpp',
                'cli/CliUtils.cpp',
                'cli/CliVerifyHsf.cpp',
                'cli/main.cpp',
                ]

srcs = ce_login_sources + cli_sources

#jsmn is a build dependency
#Get it from github
#jsmn commit ID at time of creating this project
JSMN_COMMITID = '053d3cd29200edb1bfd181d917d140c16c1f8834'
lr = run_command('ls', 'jsmn')
if lr.returncode() !=0
  r = run_command('git', 'clone', 'https://github.com/zserge/jsmn', 'jsmn')
  if r.returncode() != 0
    error(r.stdout().strip())
  endif
  r = run_command('git', '--git-dir', './jsmn/.git', 'checkout', JSMN_COMMITID)
endif

idir = include_directories(['celogin/include', './cli', 'celogin/src', './jsmn'])

if get_option('static')
  ce_login_a = static_library('celogin', cpp_args : args + ['-fPIC'], sources : ce_login_sources, dependencies : deps, soversion : '0', include_directories : idir, install : true,)
  lib_ce_login_dep = declare_dependency( include_directories : [idir] , link_with : ce_login_a)
endif

if get_option('so')
  install_headers(['include/CeLogin/CeLogin.h'], install_dir : 'include/CeLogin' )
  shared_library('celogin', cpp_args : args + ['-fPIC'], sources : srcs, dependencies : ce_login_sources, soversion : '0', include_directories : idir, install : true,)
endif

if get_option('bin')
  build_target('celogin_cli', cpp_args : args, target_type : 'executable', sources : srcs, dependencies : deps, include_directories : idir)
endif

project('ce-login', 'cpp',
  version : '1.0.0')

cpp = meson.get_compiler('cpp')

#Intended to be configured if this does not match your openssl include loc
#Should not be required if package config is found for openssl though
openssl_include_dir = '/usr/include/openssl'
#Create a symbolic link in cwd to libcrypto/libssl directories to build
#if pkgconfig and find_library calls fail
cwd = meson.current_source_dir()

libcrypto = dependency('libcrypto', required : false)
if not libcrypto.found()
  libcrypto = cpp.find_library('crypto', required : false )
  if not libcrypto.found()
    #Last resort to build with libcrypto
    crypto_inc = include_directories ( openssl_include_dir )
    libcrypto = declare_dependency( link_args : [ '-L' + cwd, '-lcrypto' ], include_directories : crypto_inc )
  endif
endif

libssl = dependency('libssl', required : false)
if not libssl.found()
  libssl = cpp.find_library('ssl', required : false)
  if not libssl.found()
    #Last resort to build with libssl
    crypto_inc = include_directories ( openssl_include_dir )
    libssl = declare_dependency( link_args : [ '-L',  '-lssl' ], include_directories : crypto_inc )
  endif
endif

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
  ce_login_a = static_library('celogin', cpp_args : args + ['-fPIC'], sources : ce_login_sources, dependencies : deps, soversion : '0', include_directories : idir, install : true)
  lib_ce_login_dep = declare_dependency( include_directories : [idir] , link_with : ce_login_a)
endif

if get_option('so')
  install_headers(['celogin/include/CeLogin.h'], install_dir : 'include/celogin' )
  shared_library('celogin', cpp_args : args + ['-fPIC'], sources : srcs, dependencies : ce_login_sources, soversion : '0', include_directories : idir, install : true)
endif

#Ce-login utility for generating access control files
if get_option('bin')
  exe = executable('celogin_cli', cpp_args : args, target_type : 'executable', sources : srcs, dependencies : deps, include_directories : idir)

#Tests to run against celogin_cli creating ACF, validating, and decoding.
#Priority is set for ordering of commands as some tests depend on each other,
#eg the ACF should be created before validating it.
#If priority is not defined then it is implicitly 0
#and higher numbers are executed first

  test('Generate ACF', exe, priority : 3, args : [ 'create',
                                                   '--machine', 'P10,dev,UNSET',
                                                   '--sourceFileName', 'none',
                                                   '--password', '0penBmc1',
                                                   '--expirationDate', '2025-12-25',
                                                   '--requestId', '1234',
                                                   '--pkey', '../p10-celogin-lab-pkey.der',
                                                   '--output', './ACFFile.bin' ])

  test('Verify ACF', exe, priority : 2, args : [ 'verify',
                                                 '--hsfFile', './ACFFile.bin',
                                                 '--publicKeyFile', '../p10-celogin-lab-pub.der',
                                                 '--password', '0penBmc1',
                                                 '--serialNumber', 'UNSET' ] )

  test('Decode ACF', exe, priority : 1, args : [ 'decode',
                                                 '--hsfFile', './ACFFile.bin',
                                                 '--publicKeyFile', '../p10-celogin-lab-pub.der'])

  test('Execute celogin_cli with no args', exe, should_fail : true)

  test('Generate ACF - Malformed param', exe, priority : -100, should_fail : true,
                                          args : [ 'create',
                                                   '--machine', 'P10,dev,UNSET',
                                                   '--sourceFileName', 'none',
                                                   '--passwordBadArgument', '0penBmc1',
                                                   '--expirationDate', '2025-12-25',
                                                   '--requestId', '1234',
                                                   '--pkey', '../p10-celogin-lab-pkey.der',
                                                   '--output', './ACFFile.bin' ] )

  test('Verify ACF - Incorrect Password', exe, priority : 1, should_fail : true,
                                          args : [ 'verify',
                                                   '--hsfFile', 'ACFFile.bin',
                                                   '--publicKeyFile', '../p10-celogin-lab-pub.der',
                                                   '--password', 'notthepassword',
                                                   '--serialNumber', 'UNSET' ] )

  test('Verify ACF - Incorrect Serial Number', exe, priority : 1, should_fail : true,
                                          args : [ 'verify',
                                                   '--hsfFile', 'ACFFile.bin',
                                                   '--publicKeyFile', '../p10-celogin-lab-pub.der',
                                                   '--password', 'notthepassword',
                                                   '--serialNumber', '123123' ] )

  test('Decode ACF - No pubkey', exe, should_fail : true,
                                          args : [ 'decode',
                                                   '--hsfFile', './ACFFile.bin',
                                                   '--publicKeyFile', 'celogin_cli'])
endif

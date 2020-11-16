project(
	'autologin',
	'c',
	license: 'GPL3',
	meson_version: '>=0.47.0',
	default_options: [
		'c_std=c11',
		'warning_level=3',
		'werror=true',
	],
)
add_project_arguments([
	'-Wundef',
	'-Wunused',
	'-Wlogical-op',
	'-Wmissing-include-dirs',
	'-Wold-style-definition', # nop
	'-Wpointer-arith',
	'-Wstrict-prototypes',
	'-Wimplicit-fallthrough',
	'-Wmissing-prototypes',
	'-Wno-unknown-warning-option',
	'-Wno-unused-command-line-argument',
	'-Wvla',
	], language: 'c')

cc = meson.get_compiler('c')
executable(
	'autologin',
	['main.c'],
	dependencies: [cc.find_library('pam', required: true)],
	install: true,
)


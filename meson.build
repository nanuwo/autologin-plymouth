project(
	'autologin',
	'c',
	license: 'GPL3',
	meson_version: '>=0.47.0',
	default_options: [
		'c_std=c11',
		'warning_level=2',
		'werror=true',
	],
)

add_project_arguments('-Wno-unused-parameter', language: 'c')
add_project_arguments('-Wno-missing-braces', language: 'c')
cc = meson.get_compiler('c')
executable(
	'autologin',
	['main.c'],
	dependencies: [cc.find_library('pam', required: true)],
	install: true,
)


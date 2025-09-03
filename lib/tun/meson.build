# Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>

# This file is part of Open5GS.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

libtun_sources = files('''
    ogs-tun.h

    host_tun_service.c

    tunio.c
'''.split())

if host_system == 'linux'
    libtun_sources += files('linux-setup.c')
elif host_system == 'windows'
    libtun_sources += files('windows-setup.c')
else
    libtun_sources += files('mac-setup.c')
endif

libtun_inc = include_directories('.')

libtun = library('ogstun',
    sources : libtun_sources,
    version : libogslib_version,
    c_args : '-DOGS_TUN_COMPILATION',
    include_directories : [libtun_inc, libinc],
    dependencies : libipfw_dep,
    install : true)

libtun_dep = declare_dependency(
    link_with : libtun,
    include_directories : [libtun_inc, libinc, libproto_inc, libcore_inc],
    dependencies : libipfw_dep)



libtun_inc = include_directories('.')
libproto_inc = include_directories('../proto')
libcore_inc = include_directories('../core')

uds_server_sources = files(''' 
    uds_server.c

    ogs-tun.h

    host_tun_service.c

    tunio.c
'''.split())

executable('uds_server', uds_server_sources,
  dependencies: [libtun_dep],
  install_rpath: libdir,
  install: true
)

uds_client_sources = files('''
    uds_client.c
    ogs-tun.h
    host_tun_service.c
    tunio.c
'''.split())

# Create the uds_client executable
executable('uds_client', uds_client_sources,
    dependencies: [libtun_dep],
    install_rpath: libdir,  # Ensure RPATH is set
    install: true
)


test_ogs_resources = files(''' 
    test_ogs_tun.c

    ogs-tun.h

    tunio.c

    host_tun_service.c

'''.split())

executable('test_ogs_tun', test_ogs_resources,
  dependencies: [libtun_dep],
  install_rpath: libdir,
  install: true
)

# unit_test_sources = files('''
#     unit_test.c
#     uds_server.c
#     linux-setup.c
# '''.split())
#
# threads_dep = dependency('threads')
#
# tun_unit_test = executable('tun_unit_test', unit_test_sources,
#   dependencies: [libtun_dep, threads_dep],
#   install_rpath: libdir,
#   install: true
# )
#
# test('tun_unit_test', tun_unit_test)

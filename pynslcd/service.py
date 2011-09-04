
# service.py - service entry lookup routines
#
# Copyright (C) 2011 Arthur de Jong
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA

import logging
import ldap.filter

import constants
import common


attmap = common.Attributes(cn='cn',
                           ipServicePort='ipServicePort',
                           ipServiceProtocol='ipServiceProtocol')
filter = '(objectClass=ipService)'


class ServiceRequest(common.Request):

    def write(self, dn, attributes, parameters):
        # get name
        name = common.get_rdn_value(dn, attmap['cn'])
        names = attributes['cn']
        if not names:
            print 'Error: entry %s does not contain %s value' % (dn, attmap['cn'])
        if 'cn' in parameters and parameters['cn'] not in names + [ name, ]:
            return # case of result entry did not match
        if not name:
            name = names.pop(0)
        elif name in names:
            names.remove(name)
        # get port number
        ( port, ) = attributes['ipServicePort']
        if not port:
            print 'Error: entry %s does not contain %s value' % (dn, attmap['ipServicePort'])
        port = int(port)
        # get protocol
        protocols = attributes['ipServiceProtocol']
        if 'ipServiceProtocol' in parameters:
            if parameters['ipServiceProtocol'] not in protocols:
                return
            protocols = ( parameters['ipServiceProtocol'], )
        # write result
        for protocol in protocols:
            self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
            self.fp.write_string(name)
            self.fp.write_stringlist(names)
            self.fp.write_int32(port)
            self.fp.write_string(protocol)


class ServiceByNameRequest(ServiceRequest):

    action = constants.NSLCD_ACTION_SERVICE_BYNAME

    def read_parameters(self, fp):
        name = fp.read_string()
        protocol = fp.read_string()
        if protocol:
            return dict(cn=name, ipServiceProtocol=protocol)
        else:
            return dict(cn=name)


class ServiceByNumberRequest(ServiceRequest):

    action = constants.NSLCD_ACTION_SERVICE_BYNUMBER

    def read_parameters(self, fp):
        number = fp.read_int32()
        protocol = fp.read_string()
        if protocol:
            return dict(ipServicePort=number, ipServiceProtocol=protocol)
        else:
            return dict(ipServicePort=number)


class ServiceAllRequest(ServiceRequest):

    action = constants.NSLCD_ACTION_SERVICE_ALL


# shadow.py - lookup functions for shadownet addresses
#
# Copyright (C) 2010, 2011 Arthur de Jong
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

import constants
import common


attmap = common.Attributes(uid='uid',
                           userPassword='"*"',
                           shadowLastChange='"${shadowLastChange:--1}"',
                           shadowMin='"${shadowMin:--1}"',
                           shadowMax='"${shadowMax:--1}"',
                           shadowWarning='"${shadowWarning:--1}"',
                           shadowInactive='"${shadowInactive:--1}"',
                           shadowExpire='"${shadowExpire:--1}"',
                           shadowFlag='"${shadowFlag:-0}"')
filter = '(objectClass=shadowAccount)'
bases = ( 'ou=people,dc=test,dc=tld', )


class ShadowRequest(common.Request):

    def write(self, dn, attributes, parameters):
        # get name and check against requested name
        names = attributes['uid']
        if not names:
            print 'Error: entry %s does not contain %s value' % ( dn, attmap['uid'] )
            return
        if 'uid' in parameters:
            if parameters['uid'] not in names:
                return
            names = ( parameters['uid'], )
        # get password
        (passwd, ) = attributes['userPassword']
        if not passwd or self.calleruid != 0:
            passwd = '*'
        # function for making an int
        def mk_int(attr):
            try:
                return
            except TypeError:
                return None
        # get lastchange date
        lastchangedate = int(attributes.get('shadowLastChange', [0])[0])
        # we expect an AD 64-bit datetime value;
        # we should do date=date/864000000000-134774
        # but that causes problems on 32-bit platforms,
        # first we devide by 1000000000 by stripping the
        # last 9 digits from the string and going from there */
        if attmap['shadowLastChange'] == 'pwdLastSet':
            lastchangedate = ( lastchangedate / 864000000000 ) - 134774
        # get longs
        mindays = int(attributes.get('shadowMin', [-1])[0])
        maxdays = int(attributes.get('shadowMax', [-1])[0])
        warndays = int(attributes.get('shadowWarning', [-1])[0])
        inactdays = int(attributes.get('shadowInactive', [-1])[0])
        expiredate = int(attributes.get('shadowExpire', [-1])[0])
        flag = int(attributes.get('shadowFlag', [0])[0])
        if attmap['shadowFlag'] == 'pwdLastSet':
            if flag & 0x10000:
                maxdays = -1
            flag = 0
        # write results
        for name in names:
            self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
            self.fp.write_string(name)
            self.fp.write_string(passwd)
            self.fp.write_int32(lastchangedate)
            self.fp.write_int32(mindays)
            self.fp.write_int32(maxdays)
            self.fp.write_int32(warndays)
            self.fp.write_int32(inactdays)
            self.fp.write_int32(expiredate)
            self.fp.write_int32(flag)


class ShadowByNameRequest(ShadowRequest):

    action = constants.NSLCD_ACTION_SHADOW_BYNAME

    def read_parameters(self, fp):
        return dict(uid=fp.read_string())


class ShadowAllRequest(ShadowRequest):

    action = constants.NSLCD_ACTION_SHADOW_ALL

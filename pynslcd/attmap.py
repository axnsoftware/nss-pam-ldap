
# attributes.py - attribute mapping functions
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

"""Module for handling attribute mappings used for LDAP searches.

>>> attrs = Attributes(uid='uid',
...                    userPassword='userPassword',
...                    uidNumber='uidNumber',
...                    gidNumber='gidNumber',
...                    gecos='"${gecos:-$cn}"',
...                    homeDirectory='homeDirectory',
...                    loginShell='loginShell')
>>> attrs.attributes()
('uid', 'userPassword', 'uidNumber', 'gidNumber', 'gecos', 'cn', 'homeDirectory', 'loginShell')
>>> attrs.value('gecos', {'cn': 'test'})
['test']
>>> attrs.search('uidNumber', 100)
'(uidNumber=100)'
>>> attrs['foo'] = '\"bar\"'
>>> attrs.get('foo', {})
['bar']
"""

# exported names
__all__ = ( 'Attributes', )


# FIXME: support multiple attribute values
# TODO: support objectSid attributes
# TODO: do more expression validity checking
# TODO: handle userPassword specially to do filtering of results


class MyIter(object):
    """Custom iterator-like class with a back() method."""

    def __init__(self, value):
        self.value = value
        self.pos = 0

    def next(self):
        self.pos += 1
        return self.value[self.pos-1]

    def back(self):
        self.pos -= 1

    def __iter__(self):
        return self


class DollarExpression(object):
    """Class for handling a variable $xxx ${xxx}, ${xxx:-yyy} or ${xxx:+yyy}
    expression."""

    def _parse_varname(self, value):
        """Read a variable name from the value iterator."""
        name = ''
        for c in value:
            if not c.isalnum():
                value.back()
                return name
            name += c

    def __init__(self, value):
        """Parse the expression as the start of a $-expression."""
        self.op = None
        self.expr = None
        c = value.next()
        if c == '{':
            self.name = self._parse_varname(value)
            c = value.next()
            if c == '}':
                return
            self.op = c + value.next()
            self.expr = Expression(value, endat='}')
        else:
            value.back()
            self.name = self._parse_varname(value)

    def value(self, variables):
        """Expand the expression using the variables specified."""
        value = variables.get(self.name, [''])[0]
        # FIXME: expand list
        if self.op == ':-':
            return value if value else self.expr.value(variables)
        elif self.op == ':+':
            return self.expr.value(variables) if value else ''
        return value

    def variables(self, results):
        """Add the variables used in the expression to results."""
        results.add(self.name)
        if self.expr:
            self.expr.variables(results)


class Expression(object):
    """Class for parsing and expanding an expression."""

    def __init__(self, value, endat=None):
        """Parse the expression as a string."""
        if not isinstance(value, MyIter):
            value = MyIter(value)
        if not endat:
            endat = value.next() # skip opening quote
        expr = []
        literal = ''
        c = value.next()
        while c != endat:
            if c == '$':
                if literal:
                    expr.append(literal)
                expr.append(DollarExpression(value))
                literal = ''
            elif c == '\\':
                literal += value.next()
            else:
                literal += c
            c = value.next()
        if literal:
            expr.append(literal)
        self.expr = expr

    def value(self, variables):
        """Expand the expression using the variables specified."""
        res = ''
        for x in self.expr:
            if hasattr(x, 'value'):
                res += x.value(variables)
            else:
                res += x
        return res

    def variables(self, results=None):
        """Return the variables defined in the expression."""
        if not results:
            results = set()
        for x in self.expr:
            if hasattr(x, 'variables'):
                x.variables(results)
        return results


class Attributes(dict):
    """Dictionary-like class for handling a list of attributes."""

    def _prepare(self):
        """Go over all values to parse any expressions."""
        updates = dict()
        for k, v in self.iteritems():
            if isinstance(v, basestring) and v[0] == '"':
                updates[k] = Expression(v)
        self.update(updates)

    def attributes(self):
        """Return a set of attributes that are referenced in this attribute
        mapping."""
        self._prepare()
        results = set()
        for value in self.itervalues():
            if hasattr(value, 'variables'):
                results.update(value.variables())
            else:
                results.add(value)
        return list(results)

    def mapped(self, variables):
        """Return a dictionary with every attribute mapped to their value from
        the specified variables."""
        results = dict()
        for k, v in self.iteritems():
            if hasattr(v, 'value'):
                results[k] = [v.value(variables)]
            else:
                results[k] = variables.get(v, [])
        return results

import binaryninja
from collections import defaultdict, namedtuple
import re

"""
Useful tutorial - http://www.rmunn.com/sqlalchemy-tutorial/tutorial.html
Creation:

# dump comes from binjadb
dump = bz2.decompress(dump).split('\n')
db = sqlalchemy.create_engine('sqlite://')
[db.raw_connection().execute(x) for x in dump]

Saving:

dump = bz2.compress('\n'.join(db2.raw_connection().iterdump()))

Instructions:

from sqlalchemy import Table, Column, String, Integer
db = sqlalchemy.create_engine('sqlite://')
meta = sqlalchemy.MetaData(db)
tags = Table('tags', meta, Column('tag', String), Column('tagname', String), Column('address', Integer), Column('function', String))
tags.create()

ti = tags.insert()
ti.execute(tagname='note', tag='vuln function', address=3, function='Func0')

list(tags.select(tags.c.tagname == 'note').execute())
"""

tagsdb = None

class TagsDatabase(object):
    """
    Database containing the dictionary of tags in the current database.

    ``TagsDatabase`` must also hold the ``BinaryView`` in order to query/add comments and query function information.

    Dict Structure::

        {
            0xdeadbeef: {
                'synopsis': 'Calls vulnerable function',
                'calls': ['gets']
            },
            0xcafebabe: {
                'synopsis': 'Wrapper around function',
                'break': '.printf "Useful wrapper"'
            },
            'synopsis': [0xdeadbeef, 0xdeadbeef],
            'calls': [0xdeadbeef],
            'break': [0xcafebabe],
        }
    """
    def __init__(self, bv):
        self._db = {}
        self._bv = bv

    def add(self, address, tagname, data):
        """
        Add a tag to the database at a given address.

        ASSUMPTION: UI comments will not be used and comments will only be added via tag system.

        There can only be one entry per tagname per address. Will also add comments for each tag at the given address.

        :param str address: Address to apply the tag to
        :param str tagname: Name of the tag being applied
        :param str data: Tag data 
        :return: None
        :Example:
            
	    >>> tags.add(here, 'note', 'testing tags')
        """
        curr_funcs = self._bv.get_functions_containing(address)

        if curr_funcs == None:
            print('WARN: Function containing address 0x{:x} not found. Not adding tag.'.format(address))
            return

        for curr_func in curr_funcs:
            if self._db.get(address) == None:
                    self._db[address] = {}

            if self._db.get(tagname) == None:
                    self._db[tagname] = set()

            if self._db.get(curr_func.name) == None:
                    self._db[curr_func.name] = set()

            self._db[address][tagname] = data
            self._db[tagname].add(address)
            self._db[curr_func.name].add(address)

            tags = self.select_addr(address)

            new_tag = ''
            for tagname, tagdata in tags.iteritems():
                new_tag += self._create_tag(tagname, tagdata)

            curr_func.set_comment_at(address, new_tag)

            """
            Propagate the function comments to function xrefs
            """
            if curr_func.start == address:
                xrefs = [xref.address for xref in self._bv.get_code_refs(address)]
                for xref in xrefs:
                    xref_funcs = self._bv.get_functions_containing(xref)
                    if curr_func == None:
                        continue

                    for xref_func in xref_funcs:
                        xref_func.set_comment_at(xref, new_tag)

    def _create_tag(self, tagname, data):
        """
        Create the string format for comments
        
        Current format:
        [TAGNAME] DATA

        :param str tagname: Name of the tag
        :param str data: Data for the given tag
        :return: Properly formatted string for the requested tag
        :rtype: str
        """
        return '[{}] {}\n'.format(tagname, data)

    def select(self, *args):
        """
        Return all tags with the given tagname 
        :param str/int/long addr/tagname: Address or Tagname
        :param str/int/long addr/tagname: Address or Tagname
        :return: Requested tags or addresses
        :rtype: dict/list/str
        :Example:

	    >>> tags.add(here, 'note', 'testing tags')

	    >>> tags.select(here)
	    {'note': 'testing tags'}

	    >>> tags.select('note')
	    [134515550L]

	    >>> tags.select(here, 'note')
	    'testing tags'

	    >>> tags.select('note', here)
	    'testing tags'
        """
        if len(args) > 2:
            print("tags.select only takes up to 2 arguments")
            return

        elif len(args) == 1: 
            arg = args[0]
            if not isinstance(arg, (long, int, str)):
                print("tags.select can only take long/ints for addresses and str for tagnames. {} not available".format(type(arg)))
                return
            if isinstance(arg, (int, long)):
                return self._db.get(arg)
            elif isinstance(arg, str):
                return self._db.get(arg, 'Tag {} not found'.format(arg))

        elif len(args) == 2:
            for arg in args:
                if not isinstance(arg, (long, int, str)):
                    print("tags.select can only take long/ints for addresses and str for tagnames. {} not available".format(type(arg)))
                    return
            if type(arg[0]) == type(arg[1]):
                print("tags.select argument are mutually exclusive str and long/int")
                return
            if isinstance(args[0], (long, int)) and isinstance(args[1], str):
                addr, tagname = args
                return self._db.get(addr, {}).get(tagname)
            elif isinstance(args[0], (str)) and isinstance(args[1], (long, int)):
                tagname, addr = args
                return self._db.get(addr, {}).get(tagname)
            else:
                print("Not sure what was given to tags.select.. shouldn't get here")

    def select_addr(self, addr, tagnames=''):
        """
        Return all tags for a given address or a subset of tags given tagnames

        :param int/long addr: Address to query for tags
        :param str/list(str) tagnames: Specific tag or tags to query for the given address
        :return: Requested tags or addresses
        :rtype: dict/list/str
        :Example:

            >>> tags.add(here, 'note', 'testing note')
            >>> tags.add(here, 'synopsis', 'MD5SUM of string')

            >>> tags.select_addr(here)
            {'note': 'testing note', 'synopsis': 'MD5SUM of string'}

            >>> tags.select_addr(here, 'synopsis')
            {'synopsis': 'MD5SUM of string'}

            >>> tags.select_addr(here, ['synopsis', 'note'])
            {'note': 'testing note', 'synopsis': 'MD5SUM of string'}
        """
        if not isinstance(addr, (int, long)):
            raise Exception("First parameter for tags.select_addr must be an address of type int or long")

        if tagnames:
            if not isinstance(tagnames, (str, list)):
                raise Exception("Second parameter for tags.select_addr must be a single tagname or a list of tagnames")

            if isinstance(tagnames, str):
                tagnames = [tagnames]
            elif isinstance(tagnames, list):
                if not all(isinstance(tagname, str) for tagname in tagnames):
                    raise Exception("All tagnames passed to tags.select_addr must be strings")

            result = {}
            for tagname in tagnames:
                result[tagname] = self._db.get(addr, {}).get(tagname)

            return result

        else:
            return self._db.get(addr)

    def select_func(self, func, tagnames=''):
        """
        Return all tags for a given function or a subset of tags given tagnames

        :param str/binaryninja.function.Funtion func: Function or function name to query for tags
        :param str/list(str) tagnames: Specific tag or tags to query for the given function
        :return: Requested tags or addresses
        :rtype: dict(tuple)
        :Example:

            # Create a few sample tags
            >>> [tags.add(ref.address, 'addr', 'My address is {}'.format(hex(ref.address))) for ref in func.down()]
            >>> [tags.add(ref.address, 'call', 'xref from {}'.format(hex(h))) for ref in func.down()]

            # Querying via function
            >>> tags.select_func(f)
            defaultdict(<type 'list'>, {'call': [(134515704L, 'xref from 0x8048bd1L'), (134515746L, 'xref from 0x8048bd1L')], 
                                        'addr': [(134515704L, 'My address is 0x8048bf8L'), (134515746L, 'My address is 0x8048c22L')]})
            >>> tags.select_func(f).keys()
            ['call', 'addr']
            >>> tags.select_func(f)['call']
            [(134515704L, 'xref from 0x8048bd1L'), (134515746L, 'xref from 0x8048bd1L')]
            >>> tags.select_func(f)['addr']
            [(134515704L, 'My address is 0x8048bf8L'), (134515746L, 'My address is 0x8048c22L')]

            # Querying via function name
            >>> tags.select_func(f.name)
            defaultdict(<type 'list'>, {'call': [(134515704L, 'xref from 0x8048bd1L'), (134515746L, 'xref from 0x8048bd1L')], 
                                        'addr': [(134515704L, 'My address is 0x8048bf8L'), (134515746L, 'My address is 0x8048c22L')]})

        """
        if isinstance(func, str):
            func_name = func

        elif isinstance(func, binaryninja.function.Function):
            func_name = func.name
        
        else:
            print("Function {} is not of type binaryninja.function.Function or str".format(func))
            return

        if func_name not in self._db:
            return defaultdict(dict)

        result = defaultdict(list)

        curr_res = defaultdict(list)

        if tagnames:
            if not isinstance(tagnames, (str, list)):
                raise Exception("Second parameter for tags.select_addr must be a single tagname or a list of tagnames")

            if isinstance(tagnames, str):
                tagnames = [tagnames]
            elif isinstance(tagnames, list):
                if not all(isinstance(tagname, str) for tagname in tagnames):
                    raise Exception("All tagnames passed to tags.select_addr must be strings")

            for tagname in tagnames:
                for addr in self._db[func]:
                    if addr not in self._db:
                        continue
                    if tagname not in self._db[addr]:
                        continue

                    curr_tag = self._db[addr][tagname]
                    tuple_res = (addr, curr_tag)
                    result[tagname].append(tuple_res)

        else:
            for addr in self._db.get(func_name, {}):
                for tagname, tag in self._db[addr].iteritems():
                    tuple_res = (addr, tag)
                    result[tagname].append(tuple_res)

        return result

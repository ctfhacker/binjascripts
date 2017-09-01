from collections import defaultdict, namedtuple
import re

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
        self.bv = bv

    def add(self, address, tagname, data):
        """
        Add a tag to the database at a given address.

        There can only be one entry per tagname per address. Will also add comments for each tag at the given address

        :param str address: Address to apply the tag to
        :param str tagname: Name of the tag being applied
        :param str data: Tag data 
        :return: None
        :Example:
            
	    >>> tags.add(here, 'note', 'testing tags')
        """
        curr_func = self.bv.get_functions_containing(address)
        if curr_func == None:
            print('WARN: Function containing address 0x{:x} not found. Not adding tag.'.format(address))
            return

        curr_func = curr_func[0]
        if self._db.get(address) == None:
                self._db[address] = {}

        if self._db.get(tagname) == None:
                self._db[tagname] = []

        self._db[address][tagname] = data
        self._db[tagname].append(address)

        curr_comment = curr_func.get_comment_at(address)
        new_tag = self._create_tag(tagname, data)
        if new_tag not in curr_comment:
            curr_func.set_comment_at(address, curr_comment + self._create_tag(tagname, data))

        if curr_func.start == address:
            xrefs = [xref.address for xref in self.bv.get_code_refs(address)]
            for xref in xrefs:
                curr_func = self.bv.get_functions_containing(xref)
                if curr_func == None:
                    continue
                curr_func = curr_func[0]
                curr_comment = curr_func.get_comment_at(xref)
                new_tag = self._create_tag(tagname, data)
                if new_tag not in curr_comment:
                    curr_func.set_comment_at(xref, curr_comment + self._create_tag(tagname, data))

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
                return self._db[arg]
            elif isinstance(args[0], str):
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
                return self._db[addr][tagname]
            elif isinstance(args[0], (str)) and isinstance(args[1], (long, int)):
                tagname, addr = args
                return self._db[addr][tagname]
            else:
                print("Not sure what was given to tags.select.. shouldn't get here")

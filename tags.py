from collections import defaultdict, namedtuple
import re

tagsdb = None

class TagsDatabase(object):
    """
    Database containing the dictionary of tags in the current database.

    TagsDatabase must also hold the BinaryView in order to query/add comments and query function information.
    """
    def __init__(self, bv):
        self._db = defaultdict(dict)
        self.bv = bv

    def add(self, address, tagname, data):
        """
        Add a tag to the database at a given address.

        There can only be one entry per tagname per address. Will also add comments for each tag at the given address

        :param str address: Address to apply the tag to
        :param str tagname: Name of the tag being applied
        :param str data: Tag data 
        :return: None
        """
        curr_func = self.bv.get_functions_containing(address)
        if curr_func == None:
            print('WARN: Function containing address 0x{:x} not found. Not adding tag.'.format(address))
            return

        curr_func = curr_func[0]
        self._db[address][tagname] = data
        curr_comment = curr_func.get_comment_at(address)
        new_tag = self.create_tag(tagname, data)
        if new_tag not in curr_comment:
            curr_func.set_comment_at(address, curr_comment + self.create_tag(tagname, data))

        if curr_func.start == address:
            xrefs = [xref.address for xref in self.bv.get_code_refs(address)]
            for xref in xrefs:
                curr_func = self.bv.get_functions_containing(xref)
                if curr_func == None:
                    continue
                curr_func = curr_func[0]
                curr_comment = curr_func.get_comment_at(xref)
                new_tag = self.create_tag(tagname, data)
                if new_tag not in curr_comment:
                    curr_func.set_comment_at(xref, curr_comment + self.create_tag(tagname, data))

    def create_tag(self, tagname, data):
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

    """
    def select(tagname):
        '''Return all tags with the given tagname'''
    """

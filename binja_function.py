from binaryninja.lowlevelil import LowLevelILOperation
from binaryninja.architecture import ReferenceSource

"""
Set in __init__.py by hook functions
"""
current_function = None
current_address = None

class BinjaFunction(object):
    def __init__(self, func):
        self._func = func 
        self._bv = func.view

    def up(self, addr=''):
        """
        Returns a list of cross references to the current function

        :return: List of addresses of cross references to the current function
        :rtype: List(ReferenceSource)
        :Example:
            
            >>> [ref.address for ref in func.up()]
            [134516073L, 134514459L]

            >>> [(ref.function.name, ref.address) for ref in func.up()]
            [('sub_8048cad', 134516073L), ('main', 134514459L)]

            >>> [ref.address for ref in func.up(h)]
            [134516073L, 134514459L]
        """
        curr_func = self._func
        if addr:
            curr_func = self._bv.get_functions_containing(addr)[0]

        return self._bv.get_code_refs(curr_func.start)

    def name(self, addr=''):
        """
        Returns the name of the function containing an address

        :param int/long addr: Address to look for containing function
        :return: Name of function containing an address
        :rtype: str
        :Example:

            >>> func.name()
            'main'

            >>> func.name(h)
            'main'
        """
        if not addr:
            addr = current_address

        try:
            return self._bv.get_functions_containing(addr)[0].name
        except IndexError:
            return ''

    def down(self, addr=''):
        """
        Returns a list of cross references to calls in the current function

        Note: Does not current handle indirect calls

        :return: List of addresses of cross references to the current function
        :rtype: List(ReferenceSource)
        :Example:

            >>> [(hex(ref.address), ref.function.name, hex(ref.function.start)) for ref in func.down()]
            [('0x80485dcL', '__libc_start_main', '0x8048580L')]
        """
        curr_func = self._func
        if addr:
            curr_func = self._bv.get_functions_containing(addr)[0]

        calls = []
        for bb in curr_func.low_level_il:
            for il in bb:
                if il.operation != LowLevelILOperation.LLIL_CALL:
                    continue

                func = self._bv.get_function_at(il.dest.constant)
                calls.append(ReferenceSource(func, None, il.address))

        return calls

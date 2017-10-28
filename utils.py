from binaryninja.mediumlevelil import MediumLevelILOperation

class Utils(object):
    def __init__(self, bv):
        self._bv = bv

    def find_cmp(self, const):
        """
        Find all comparisons that compare against a given constant

        :param int const: Constant to look for
        :return: List of tuples
        :rtype: list(tuple)
        :Example:

            # Create a few sample tags
            >>> utils.find_cmp(0x5a4d)
            ('0x18002a2d2L', <il: if (rax_5.eax != 0x5a4d) then 31 @ 0x18002a312 else 34 @ 0x18002a2d4>)
            ('0x18002adf1L', <il: if (rax_5.eax != 0x5a4d) then 15 @ 0x18002ae09 else 40 @ 0x18002adf3>)
            ('0x18002afe2L', <il: if (rax_46.eax != 0x5a4d) then 44 @ 0x18002aff0 else 116 @ 0x18002afe4>)
            ('0x18002b3c2L', <il: if (rax_2.eax != 0x5a4d) then 5 @ 0x18002b3fa else 11 @ 0x18002b3c4>)
        """
        cmps = []
        for func in self._bv.functions:
            for bb in func.medium_level_il:
                for il in bb:
                    try:
                        if il.operation == MediumLevelILOperation.MLIL_IF and il.condition.right.constant == const:
                            cmps.append((il.address, il))
                    except AttributeError:
                        pass

        return cmps

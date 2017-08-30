"""
Set in __init__.py by hook functions
"""
current_function = None
current_address = None

class BinjaFunction(object):
    _function = None
    def __init__(self, func):
        self._function = None

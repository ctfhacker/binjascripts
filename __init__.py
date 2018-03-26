from binaryninja import scriptingprovider

"""
Binjascripts custom modules
"""
import binja_function
import binja_view
import tags
from utils import Utils
import slices

import cPickle as pickle

curr_init = scriptingprovider.PythonScriptingInstance.__init__

def new_init(self, provider):
    func = None
    curr_init(self, provider)

    """
    Hook perform_set_current_function
    """
    def new_set_current_function(new_func):
        self.interpreter.current_func = new_func
        binja_function.current_function = new_func

        locals = self.interpreter.locals
        locals['f'] = binja_function.current_function
        locals['llil'] = binja_function.current_function.low_level_il if binja_function.current_function else 'Not Available'
        locals['llilssa'] = binja_function.current_function.low_level_il.ssa_form if binja_function.current_function else 'Not Available'
        locals['mlil'] = binja_function.current_function.medium_level_il if binja_function.current_function else 'Not Available'
        locals['mlilssa'] = binja_function.current_function.medium_level_il.ssa_form if binja_function.current_function else 'Not Available'
        locals['h'] = binja_function.current_address
        locals['tags'] = tags.tagsdb
        locals['func'] = binja_function.BinjaFunction(binja_function.current_function) if binja_function.current_function else 'Not Available'
        locals['utils'] = Utils(binja_view.current_view)
        locals['slices'] = slices

    self.perform_set_current_function = new_set_current_function

    """
    Hook perform_set_current_function
    """
    def new_set_current_binary_view(new_view):
        # Store old TagsDB in old View
        if self.interpreter.current_view and tags.tagsdb:
            tags.tagsdb._bv = None
            self.interpreter.current_view.store_metadata('tagsdb', pickle.dumps(tags.tagsdb))

        # Set new view
        self.interpreter.current_view = new_view
        binja_view.current_view = new_view
        
        if not new_view:
            return

        # Load current view's TagsDB
        try:
            tags.tagsdb = pickle.loads(new_view.query_metadata('tagsdb'))
            tags.tagsdb._bv = new_view
        except KeyError:
            tags.tagsdb = tags.TagsDatabase(new_view)

    self.perform_set_current_binary_view = new_set_current_binary_view
    """
    End Hook perform_set_current_function
    """

    """
    Hook perform_set_current_address
    """
    def new_set_current_address(new_address):
        self.interpreter.current_addr = new_address
        binja_function.current_address = new_address

    self.perform_set_current_address = new_set_current_address
    """
    End Hook perform_set_current_address
    """

scriptingprovider.PythonScriptingInstance.__init__ = new_init


from binaryninja import scriptingprovider
import binja_function
import binja_view
import binja_database
import pickle

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

    self.perform_set_current_function = new_set_current_function

    """
    Hook perform_set_current_function
    """
    def new_set_current_binary_view(new_view):
        # Store old TagsDB in old View
        if self.interpreter.current_view and binja_database.tagsdb:
            self.interpreter.current_view.store_metadata('tagsdb', pickle.dumps(binja_database.tagsdb))

        # Set new view
        self.interpreter.current_view = new_view
        binja_view.current_view = new_view
        
        if not new_view:
            return

        # Load current view's TagsDB
        try:
            binja_database.tagsdb = pickle.loads(new_view.query_metadata('tagsdb'))
        except KeyError:
            binja_database.tagsdb = binja_database.TagsDatabase(new_view)

    self.perform_set_current_binary_view = new_set_current_binary_view

    """
    Hook perform_set_current_address
    """
    def new_set_current_address(new_address):
        self.interpreter.current_addr = new_address
        binja_function.current_address = new_address

    self.perform_set_current_address = new_set_current_address

    """
    Hook interpreter.runsource
    """
    interpreter_thread = self.interpreter
    curr_runsource = interpreter_thread.interpreter.runsource
    def new_runsource(*args):
        locals = interpreter_thread.locals
        locals['func'] = binja_function.current_function
        locals['mlil'] = binja_function.current_function.medium_level_il
        locals['mlilssa'] = binja_function.current_function.medium_level_il.ssa_form
        locals['h'] = binja_function.current_address
        locals['tags'] = binja_database.tagsdb
        curr_runsource(*args)

    interpreter_thread.interpreter.runsource = new_runsource

scriptingprovider.PythonScriptingInstance.__init__ = new_init


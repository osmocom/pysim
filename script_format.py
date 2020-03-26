
class ScriptFormat():

    def parse_process(self, text, stmt_cb, stmt_cb_kwargs={}):
        p = self.parse_xform(text)
        #print(p.pretty())
        for stmt in p.children:
            stmt_cb(stmt, **stmt_cb_kwargs)

    def parse_process_file(self, fname, stmt_cb, stmt_cb_kwargs={}):
        f = open(fname, "r")
        text = f.read()
        return self.parse_process(text, stmt_cb, stmt_cb_kwargs)

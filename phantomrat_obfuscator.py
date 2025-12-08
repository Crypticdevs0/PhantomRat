import ast
import random
import string

class Obfuscator(ast.NodeTransformer):
    def __init__(self):
        self.var_map = {}
        self.counter = 0

    def generate_name(self):
        self.counter += 1
        return 'var' + str(self.counter)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            if node.id not in self.var_map:
                self.var_map[node.id] = self.generate_name()
            node.id = self.var_map[node.id]
        elif isinstance(node.ctx, ast.Load):
            if node.id in self.var_map:
                node.id = self.var_map[node.id]
        return node

    def visit_FunctionDef(self, node):
        # Rename function name
        node.name = self.generate_name()
        self.generic_visit(node)
        return node

def obfuscate_code(code):
    tree = ast.parse(code)
    obfuscator = Obfuscator()
    obfuscated_tree = obfuscator.visit(tree)
    return ast.unparse(obfuscated_tree)  # Python 3.9+

if __name__ == "__main__":
    # Example code to obfuscate
    code = """
def hello():
    x = 10
    y = x + 5
    print(y)
hello()
"""
    obfuscated = obfuscate_code(code)
    print(obfuscated)
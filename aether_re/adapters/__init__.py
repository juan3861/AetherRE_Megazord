"""Adaptadores opcionais para ferramentas externas (Ghidra, Rizin, Frida, Unicorn, angr, Binary Ninja)."""

from .ghidra import GhidraAdapter
from .rizin import RizinAdapter
from .frida_dyn import FridaAdapter
from .unicorn_emu import UnicornAdapter
from .angr import AngrAdapter
from .binaryninja import BinaryNinjaAdapter


"""AetherRE Megazord — Native MCP Server (Model Context Protocol).

Implementa um servidor MCP (JSON-RPC 2.0 via stdio) completo e de alta fidelidade
para que assistentes de IA (Claude Code, Cursor, Codex, Gemini CLI, Antigravity)
possam acionar diretamente o arsenal forense de engenharia reversa do Megazord.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from dataclasses import asdict

from aether_re import __codename__, __version__
from aether_re.capabilities import analyze_target_capabilities
from aether_re.engines import strings_decode, triage
from aether_re.firmware_layout import qualify_firmware_layout
from aether_re.pipeline import adapters_status, run_megazord
from aether_re.source import analyze_python_project


PROTOCOL_VERSION = "2024-11-05"

SERVER_INFO = {
    "name": "aetherre-megazord",
    "version": __version__,
    "description": f"AetherRE {__codename__} — Supreme Universal Reverse Engineering & Forensic Evidence Server",
}

TOOLS = [
    {
        "name": "aether_status",
        "description": "Retorna o status dos motores nativos (Capstone, pefile), adaptadores (Ghidra, Rizin, Angr, ILSpy, Vineflower, REA) e locks da toolchain.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "aether_triage",
        "description": "Triage forense rápida de qualquer ficheiro ou binário: calcula SHA-256, detecta formato mágico (PE, ELF, Mach-O, WASM, DEX, Zip) e afere entropia de Shannon para detectar empacotamento ou criptografia.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o ficheiro a analisar.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_inspect",
        "description": "Análise estática multi-engine completa do alvo binário. Extrai importações, exportações, cabeçalhos, funções descompiladas e findings de segurança com voto de consenso.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário ou aplicação.",
                },
                "profile": {
                    "type": "string",
                    "description": "Perfil opcional: auto, native-pe, native-elf, dotnet, android-apk, wasm, macho, jvm, firmware.",
                    "default": "auto",
                },
                "shallow": {
                    "type": "boolean",
                    "description": "Se verdadeiro, pula descompilação profunda para resposta imediata.",
                    "default": False,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_detect_capabilities",
        "description": "Motor semântico estilo CAPA. Mapeia capacidades forenses e de malware (anti-debug, injeção de código, persistência, criptografia, comunicação C2) categorizadas sob o framework MITRE ATT&CK.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o ficheiro alvo.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_strings_forensic",
        "description": "Extrai e classifica strings do binário em categorias forenses especializadas: URLs, endereços IPv4/IPv6, chaves de Registro, caminhos de ficheiros e padrões criptográficos.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o ficheiro alvo.",
                },
                "min_length": {
                    "type": "integer",
                    "description": "Comprimento mínimo da string (padrão: 5).",
                    "default": 5,
                },
                "max_count": {
                    "type": "integer",
                    "description": "Número máximo de strings categorizadas a retornar.",
                    "default": 100,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_firmware_qualify",
        "description": "Valida o layout físico e fronteiras de um blob de firmware em relação a um contrato firmware-layout.v1 (arquitetura, base address, endianness e regiões não sobrepostas).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o blob de firmware.",
                },
                "layout_file": {
                    "type": "string",
                    "description": "Caminho absoluto para o ficheiro JSON de layout (firmware-layout.v1).",
                },
            },
            "required": ["target", "layout_file"],
        },
    },
    {
        "name": "aether_source_analyze",
        "description": "Análise estática de código-fonte de um projeto Python via AST sem importar nem executar nenhum módulo.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "root_dir": {
                    "type": "string",
                    "description": "Diretório raiz do projeto a ser analisado.",
                },
            },
            "required": ["root_dir"],
        },
    },
    {
        "name": "aether_unpack",
        "description": "Desempacota containers e pacotes (Electron ASAR, pacotes ZIP/JAR/APK, arquivos TAR, executáveis PyInstaller ou streams de firmware embutidos) com verificação estrita de zip-slip e contenção fail-closed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o ficheiro de container.",
                },
                "out_dir": {
                    "type": "string",
                    "description": "Diretório de destino para extrair os ficheiros.",
                },
                "max_files": {
                    "type": "integer",
                    "description": "Limite máximo de ficheiros a extrair (padrão: 5000).",
                    "default": 5000,
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Limite máximo de bytes totais a extrair (padrão: 512MB).",
                    "default": 536870912,
                },
            },
            "required": ["target", "out_dir"],
        },
    },
    {
        "name": "aether_symbolic_explore",
        "description": "Executa exploração simbólica delimitada de caminhos via motor angr para avaliar alcançabilidade de endereços alvos sem execução arbitrária.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário nativo a explorar.",
                },
                "find_address": {
                    "type": "string",
                    "description": "Endereço hexadecimal do bloco básico ou função a alcançar (ex: '0x401230').",
                },
                "avoid_addresses": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista de endereços hexadecimais a evitar (ex: ['0x401250']).",
                    "default": [],
                },
                "max_steps": {
                    "type": "integer",
                    "description": "Limite máximo de passos de execução simbólica (padrão: 50).",
                    "default": 50,
                },
                "timeout_s": {
                    "type": "integer",
                    "description": "Timeout em segundos (padrão: 30).",
                    "default": 30,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_binary_diff",
        "description": "Compara estruturalmente dois binários/executáveis estilo BinDiff e Diaphora. Analisa deltas de imports, exports, seções, strings e identifica funções idênticas, modificadas (1-day patches) e adicionadas.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_a": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário original (base).",
                },
                "target_b": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário modificado ou com patch.",
                },
                "deep": {
                    "type": "boolean",
                    "description": "Se verdadeiro, extrai consenso de descompilação de funções para análise profunda.",
                    "default": False,
                },
            },
            "required": ["target_a", "target_b"],
        },
    },
    {
        "name": "aether_generate_yara",
        "description": "Sintetiza regras de detecção forenses de alta fidelidade (YARA e Sigma) para SIEM/EDR a partir do binário, suprimindo ruídos e falsos positivos.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário alvo.",
                },
                "rule_name": {
                    "type": "string",
                    "description": "Nome personalizado para a regra YARA.",
                },
                "description": {
                    "type": "string",
                    "description": "Descrição personalizada para a regra.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_export_graph",
        "description": "Exporta o grafo de chamadas de funções (Callgraph) para visualização em Mermaid (Markdown), Graphviz DOT ou JSON Graph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário alvo.",
                },
                "format": {
                    "type": "string",
                    "enum": ["mermaid", "dot", "json"],
                    "description": "Formato de saída do grafo (padrão: mermaid).",
                    "default": "mermaid",
                },
                "max_nodes": {
                    "type": "integer",
                    "description": "Limite máximo de nós no grafo (padrão: 150).",
                    "default": 150,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_function_simhash",
        "description": "Calcula vetorização SimHash de 64 bits para funções binárias com normalização PalmTree (Google Project Zero / SAFE style).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário alvo.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_packer_detect",
        "description": "Detecta empacotadores (UPX, ASPack, Themida, VMProtect, PyInstaller) e compiladores (.NET, Go, Rust, GCC, MSVC) com entropia de Shannon em janela deslizante.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o ficheiro binário a analisar.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_graph_analytics",
        "description": "Calcula métricas topológicas, complexidade ciclomática de McCabe (M = E - N + 2P), componentes fortemente conexos (Tarjan/NetworkX) e análise de hubs sobre o grafo de chamadas.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário alvo.",
                },
                "deep": {
                    "type": "boolean",
                    "description": "Se verdadeiro, ativa descompilação profunda para enriquecer o grafo.",
                    "default": False,
                },
                "max_nodes": {
                    "type": "integer",
                    "description": "Limite máximo de nós no grafo (padrão: 150).",
                    "default": 150,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_cfg_dominance",
        "description": "Calcula árvore de dominância (idom), fronteira de dominância (DF) e laços naturais sobre o CFG da função/binário.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário alvo.",
                },
                "deep": {
                    "type": "boolean",
                    "description": "Se verdadeiro, ativa descompilação profunda para enriquecer o grafo.",
                    "default": False,
                },
                "max_nodes": {
                    "type": "integer",
                    "description": "Limite máximo de nós no grafo (padrão: 150).",
                    "default": 150,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_deobfuscate",
        "description": "Simplifica expressões Mixed Boolean-Arithmetic (MBA) e avalia predicados opacos (Bogus Control Flow).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "expr": {
                    "type": "string",
                    "description": "Expressão algébrica ou predicado a simplificar.",
                },
            },
            "required": ["expr"],
        },
    },
    {
        "name": "aether_abi_infer",
        "description": "Infere convenção de chamada (cdecl, stdcall, fastcall, win64, sysv64) e protótipo de função da função alvo.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário alvo.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_taint_slice",
        "description": "Calcula fatiamento de mancha (Taint Slicing) do PDG da fonte (source) ao sumidouro crítico (sink) para detecção de vulnerabilidades.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário alvo.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_struct_recovery",
        "description": "Reconstrói layouts de estruturas C/C++, campos e padding a partir de acessos à memória (Hex-Rays / Ghidra style).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Caminho absoluto para o binário alvo.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "aether_check_feasibility",
        "description": "Verifica viabilidade simbólica (SAT/UNSAT) e consistência intervalar de restrições de caminho em bifurcações.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "constraints": {
                    "type": "string",
                    "description": "Restrições relacionais separadas por ponto-e-vírgula (ex: 'x > 10; x < 5').",
                },
            },
            "required": ["constraints"],
        },
    },
    {
        "name": "aether_ghidra_decompile",
        "description": "Exportação estática C/High P-Code pelo Ghidra, com inventário por endereço e tipos observados; pseudo-fonte não é fonte original.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário (PE/ELF)."},
                "type_injection": {"type": "boolean", "description": "Opção legada: exporta tipos observados, sem injetar hipóteses cJSON ou provar recuperação de tipos.", "default": False},
                "ir_function": {"type": "string", "maxLength": 4096, "description": "Identidade hash!space:address ou nome único para retornar o grafo High P-Code validado dessa função."},
                "reconstruct_function": {"type": "string", "maxLength": 4096, "description": "Reconstrução C escalar via High P-Code/C-Tree por identidade ou nome único; efeitos sem modelo abstêm."},
                "memory_model": {"type":"string","enum":["bounded-bytes.v1","bounded-bytes.v2"],"description":"Hipótese explícita: v1 região contígua, v2 regiões esparsas; exige reconstruct_function. Não recupera ABI nem prova equivalência binária."},
                "memory_derivation": {"type":"string","maxLength":32768,"description":"Bundle local de mapa custodiado para o mesmo alvo; exige memory_model e reconstruct_function."},
                "call_model": {"type":"string","enum":["bounded-direct-pure-calls.v1","bounded-direct-effects-calls.v1","bounded-ms-x64-stack-values.v1"],"description":"Composição condicional de chamadas diretas: perfil puro ou efeitos com terceiro estado/rastro de operações; exige memory_model bounded-bytes.v2 e reconstruct_function. Não recupera ABI nem certifica comportamento binário."},
                "derive_frame_function": {"type":"string","maxLength":4096,"description":"Seleciona programa derivado condicional por identidade ou nome único; exige frame_fact. Não admite perfil nativo ou ABI."},
                "frame_fact": {"type":"string","maxLength":32768,"description":"Caminho local do JSON limitado de hipótese de frame; usado somente com derive_frame_function."},
                "frame_runtime": {"type":"string","enum":["invocation-arena.v1"],"description":"Arena lógica para uma rota explícita de modelo derivado. Não admite perfil nativo ou ABI."},
                "observe_frame_function": {"type":"string","maxLength":4096,"description":"Observa prefixo estático de endereço Windows x64 e deriva modelo; requer frame_object_bytes e frame_language_dir. Não admite frame nativo."},
                "frame_object_bytes": {"type":"integer","minimum":1,"maximum":4096,"description":"Extensão solicitada, não inferida dos efeitos do callee."},
                "frame_language_dir": {"type":"string","maxLength":32768,"description":"Fontes x86 declaradas para o layout de registros; não atesta autenticidade da toolchain."},
                "ghidra_runtime_lock": {"type":"string","maxLength":32768,"description":"Pin local completo de Ghidra/JDK, verificado antes e depois do worker. Não autentica aquisição ou execução imutável."},
                "debug_pdb": {"type":"string","description":"PDB local opcional para adaptador de retorno; exige dia_helper/dia_dll e reconstruct_function."},
                "dia_helper": {"type":"string","description":"Helper DIA explícito e hashado; ferramenta de análise, não alvo."},
                "dia_dll": {"type":"string","description":"DLL DIA explícita e hashada."},
                "timeout": {"type": "integer", "description": "Timeout em segundos (padrão: 300).", "default": 300}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_webcrack",
        "description": "Descompactação de pacotes Webpack/Rollup, desachatamento de controle de fluxo e desofuscação de arrays de strings via webcrack 2.16.0.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o arquivo JavaScript/TypeScript."},
                "out_dir": {"type": "string", "description": "Diretório de saída para os módulos descompactados."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_minidump_audit",
        "description": "Auditoria forense de arquivos de despejo de memória Windows MiniDump (.dmp) para módulos carregados e páginas de memória RWX com permissões perigosas.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o arquivo .dmp."}
            },
            "required": ["target"]
        }
    },
            {
        "name": "aether_golang_recover",
        "description": "Extrai símbolos, funções, pacotes e metadados de executáveis Go stripped (GoReSym / pclntab).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário Go alvo."}
            },
            "required": ["target"]
        }
    },
{
        "name": "aether_detect_crypto",
        "description": "Varre binários para constantes criptográficas, S-Boxes (AES, SM4), tabelas SHA/MD5/CRC32 e chaves (FindCrypt/SignSrch).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_audit_authenticode",
        "description": "Audita assinatura Authenticode PE (PKCS#7), verifica digest PE, Rich Header, mitigações ASLR/DEP/CFG e overlay.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário PE alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_elf_dwarf_audit",
        "description": "Analisa binários ELF32/64, mitigações (RELRO, NX, PIE, Canary, Fortify) e extrai structs, funções e linhas DWARF.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário ELF alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_macho_audit",
        "description": "Analisa binários Mach-O 32/64/Fat, CodeSignature (cdhash/team_id/entitlements), segmentos e símbolos ObjC/Swift.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário Mach-O alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_rust_recover",
        "description": "Extrai versão rustc, dependências de crates Cargo, paths .rs e símbolos Rust demangled de binários stripped.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário Rust alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_firmware_audit",
        "description": "Analisa imagens de firmware: UEFI Firmware Volumes, U-Boot uImage, FDT/DTB, SquashFS, streams comprimidos e entropia.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para a imagem de firmware alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_python_audit",
        "description": "Analisa bytecode Python (.pyc 3.8..3.14) e extrai Tabela de Conteúdos (TOC) de executáveis PyInstaller.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o arquivo .pyc ou executável PyInstaller."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_cpp_rtti",
        "description": "Recupera classes C++ RTTI (MSVC/Itanium), hierarquia de herança e VTables sem executar o binário.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário C++ alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_api_hash_resolve",
        "description": "Resolve hashes de API ofuscados (ROR13, DJB2, FNV-1a, CRC32) em shellcode e binários.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário ou shellcode alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_dotnet_audit",
        "description": "Inspeciona metadados CLR .NET (BSJB, #Strings, #US User Strings) de forma estática offline.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o assembly .NET alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_floss_strings",
        "description": "Reconstrói stack strings x86/x64, decodifica strings XOR de byte único e extrai Base64 (FLARE-FLOSS).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_ole_macro",
        "description": "Extrai streams OLE2/CFB, descompacta macros VBA (MS-OVBA) e detecta gatilhos AutoExec e indicadores suspeitos (oletools).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o documento/artefato OLE2 alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_driver_audit",
        "description": "Audita drivers de kernel Windows (.sys/PE), conformidade HVCI, violações W^X e primitivas BYOVD (MSRC/pe-sieve).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário PE/driver alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_vmlinux_carve",
        "description": "Extrai imagens de kernel Linux compactadas (bzImage/vmlinuz/Image.xz), banners e símbolos kallsyms (vmlinux-to-elf).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para a imagem de kernel ou firmware alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_dex_audit",
        "description": "Analisa bytecode Android Dalvik DEX (.dex) e containers APK (classes, métodos, libs nativas JNI e indicadores de reflexão/DexClassLoader) sem exigir JVM.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o arquivo .dex ou .apk alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_wasm_audit",
        "description": "Inspeciona binários WebAssembly (.wasm), seções LEB128, imports, exports, capacidades WASI e strings de segmentos Data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o módulo .wasm alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_cfi_audit",
        "description": "Audita Intel CET (endbr64/endbr32), chamadas/saltos indiretos e superfície de gadgets (pop-ret, stack-pivot, syscall-ret) para avaliação de endurecimento CFI.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o binário alvo."}
            },
            "required": ["target"]
        }
    },
    {
        "name": "aether_installer_audit",
        "description": "Detecta e extrai metadados de instaladores InnoSetup, NSIS, Microsoft Cabinet (MSCF) e overlays 7z/RAR SFX.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Caminho absoluto para o instalador ou binário alvo."}
            },
            "required": ["target"]
        }
    },
{
        "name": "aether_ground_truth_eval",
        "description": "Compara características estruturais e procura contraprovas comportamentais num modelo explícito de C inteiro32 puro. Score estrutural não mede fidelidade semântica; memória/chamadas/controle não suportados retornam inconclusivo.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_c": {"type": "string", "description": "Caminho para o código C original."},
                "decompiled_c": {"type": "string", "description": "Código C descompilado para avaliar."},
                "function_name": {"type": "string", "description": "Nome da função a comparar."}
            },
            "required": ["source_c", "decompiled_c", "function_name"]
        }
    },
]


def _categorize_strings(raw_strings: list[str], max_count: int = 100) -> dict[str, list[str]]:
    categories: dict[str, list[str]] = {
        "urls": [],
        "ips": [],
        "registry_keys": [],
        "file_paths": [],
        "crypto_or_hashes": [],
        "others": [],
    }

    url_rx = re.compile(r"^https?://[^\s]+", re.IGNORECASE)
    ip_rx = re.compile(r"^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$")
    reg_rx = re.compile(r"^(?:HKEY_|Software\\Microsoft|System\\CurrentControlSet)", re.IGNORECASE)
    path_rx = re.compile(r"^(?:[a-zA-Z]:\\|/(?:usr|etc|bin|lib|var|tmp|home)/)", re.IGNORECASE)
    hex_rx = re.compile(r"^[0-9a-fA-F]{32,64}$")

    for s in raw_strings:
        s_clean = s.strip()
        if not s_clean:
            continue
        if url_rx.search(s_clean):
            if len(categories["urls"]) < max_count:
                categories["urls"].append(s_clean)
        elif ip_rx.search(s_clean):
            if len(categories["ips"]) < max_count:
                categories["ips"].append(s_clean)
        elif reg_rx.search(s_clean):
            if len(categories["registry_keys"]) < max_count:
                categories["registry_keys"].append(s_clean)
        elif path_rx.search(s_clean):
            if len(categories["file_paths"]) < max_count:
                categories["file_paths"].append(s_clean)
        elif hex_rx.match(s_clean):
            if len(categories["crypto_or_hashes"]) < max_count:
                categories["crypto_or_hashes"].append(s_clean)
        else:
            if len(categories["others"]) < max_count:
                categories["others"].append(s_clean)

    return categories


class AetherMcpDispatcher:
    """Despachante de comandos e ferramentas para o servidor MCP."""
    @staticmethod
    def handle_ghidra_decompile(target: str, type_injection: bool = False, timeout: int = 300, ir_function: str | None = None, reconstruct_function: str | None = None, debug_pdb: str | None = None, dia_helper: str | None = None, dia_dll: str | None = None, memory_model: str | None = None, memory_derivation: str | None = None, call_model: str | None = None, derive_frame_function: str | None = None, frame_fact: str | None = None, observe_frame_function: str | None = None, frame_object_bytes: int | None = None, frame_language_dir: str | None = None, ghidra_runtime_lock: str | None = None, frame_runtime: str | None = None) -> dict[str, Any]:
        from aether_re.ghidra_headless_bridge import GhidraHeadlessBridge
        from aether_re.frame_request import validate_frame_request,read_frame_fact
        from aether_re.native_frame_request import (validate_native_frame_request,read_native_frame_inputs,
            snapshot_native_frame_inputs,native_input_destination)
        native_inputs=None
        from aether_re.frame_request import validate_frame_runtime_request,frame_program_succeeded
        try:validate_frame_runtime_request(frame_runtime,derive_frame_function,observe_frame_function)
        except ValueError as exc:
            return dict(success=False,status='frame_runtime_configuration_invalid',error_message=str(exc))
        frame_options={} if frame_runtime is None else dict(frame_runtime=frame_runtime)
        try:
            validate_native_frame_request(observe_frame_function,frame_object_bytes,frame_language_dir,
                derive_frame_function=derive_frame_function,frame_fact=frame_fact,reconstruct_function=reconstruct_function,
                memory_model=memory_model,memory_derivation=memory_derivation,call_model=call_model,
                debug_pdb=debug_pdb,dia_helper=dia_helper,dia_dll=dia_dll)
            if observe_frame_function is not None:
                native_inputs=snapshot_native_frame_inputs(read_native_frame_inputs(target,frame_language_dir),native_input_destination())
        except (OSError,ValueError,ImportError) as exc:
            return dict(success=False,status='native_frame_configuration_invalid',error_message=str(exc)[:300])
        frame_data=None;frame_intake=None
        try:
            validate_frame_request(derive_frame_function,frame_fact,reconstruct_function=reconstruct_function,memory_model=memory_model,
                memory_derivation=memory_derivation,call_model=call_model,debug_pdb=debug_pdb,dia_helper=dia_helper,dia_dll=dia_dll)
            if derive_frame_function is not None:frame_data,frame_intake=read_frame_fact(frame_fact)
        except (OSError,ValueError) as exc:
            return dict(success=False,status='frame_configuration_invalid',error_message=str(exc)[:300])
        from aether_re.call_closure import validate_call_configuration
        try:validate_call_configuration(call_model,memory_model,reconstruct_function)
        except ValueError as exc:return dict(success=False,status='call_configuration_invalid',error_message=str(exc))
        memory_options={}
        if call_model is not None:memory_options['call_model']=call_model
        if memory_derivation is not None:
            from aether_re.native_memory_custody import validate_memory_reference,admit_memory_for_target
            try:
                validate_memory_reference(memory_derivation,memory_model,reconstruct_function)
                memory_options['_memory_context']=admit_memory_for_target(memory_derivation,target)
            except (OSError,ValueError) as exc:
                return dict(success=False,status='memory_derivation_invalid',error_message=str(exc)[:300])
        if memory_model is not None and (memory_model not in ('bounded-bytes.v1','bounded-bytes.v2') or not isinstance(reconstruct_function,str) or not reconstruct_function.strip()):
            return dict(success=False,status='memory_configuration_invalid',error_message='requires a supported bounded-bytes model and reconstruct_function')
        debug_paths=(debug_pdb,dia_helper,dia_dll)
        if any(p is not None for p in debug_paths) and (any(not isinstance(p,str) or not 1<=len(p)<=32768 for p in debug_paths) or not reconstruct_function):
            return dict(success=False,status='debug_configuration_invalid',error_message='requires reconstruct_function, debug_pdb, dia_helper and dia_dll')
        if ghidra_runtime_lock is not None:
            from aether_re.ghidra_runtime_lock import read_ghidra_runtime_lock
            try:read_ghidra_runtime_lock(ghidra_runtime_lock)
            except (OSError,ValueError,TypeError) as exc:
                return dict(success=False,status='runtime_lock_configuration_invalid',error_message=str(exc)[:300])
        bridge = GhidraHeadlessBridge(**({'runtime_lock':str(ghidra_runtime_lock)} if ghidra_runtime_lock is not None else {}))
        script = "DecompileWithTypeInjection.java" if type_injection else "DecompileAllFunctions.java"
        backend_target=native_inputs['target_path'] if native_inputs is not None else target
        res = bridge.decompile_binary(backend_target, timeout_seconds=timeout, script_name=script,
            **({'temp_work_dir':str(Path(native_inputs['target_path']).parent/'ghidra-export')} if native_inputs is not None else {}))
        payload = {
            "success": res.success,
            "status": res.status,
            "type_policy": res.type_policy,
            "ir_coverage": res.ir_coverage(),
            "limitations": res.limitations,
            "binary_path": res.binary_path,
            "target_sha256": res.target_sha256,
            "worker_execution": res.worker_execution,
            "execution_scope": "static_decompilation_no_target_execution",
            "total_functions": res.total_functions,
            "decompiled_functions": res.decompiled_functions,
            "elapsed_seconds": res.elapsed_seconds,
            "functions_summary": {k: {"name": v.name, "address": v.address, "success": v.success, "params": v.params, "return_type": v.return_type, "signature_source": v.signature_source, "ir_summary": v.ir_preview(), "c_snippet": (v.decompiled_c or '')[:200]} for k, v in list(res.functions.items())[:30]},
            "functions_returned": min(30,len(res.functions)),
            "functions_truncated": len(res.functions)>30,
            "error_message": res.error_message,
        }
        if native_inputs is not None:
            payload['native_frame_input_receipt']=native_inputs['receipt']
            payload['native_frame_export']=dict(artifact_dir=res.artifact_dir,artifact_hashes=dict(res.artifact_hashes))
        if ghidra_runtime_lock is not None:
            payload['runtime_lock_export']=dict(artifact_dir=res.artifact_dir,artifact_hashes=dict(res.artifact_hashes))
        if ir_function is not None:
            try:
                payload["function_ir"] = res.select_ir_graph(ir_function)
            except ValueError as exc:
                payload.update(success=False, export_status=res.status, status="ir_selection_failed", error_message=str(exc))
        if reconstruct_function is not None:
            try:
                payload['function_reconstruction']=res.select_reconstruction(reconstruct_function,debug_pdb=debug_pdb,dia_helper=dia_helper,dia_dll=dia_dll,memory_model=memory_model,**memory_options)
                if payload['function_reconstruction']['status']!='complete':
                    raise ValueError('ghidra_reconstruction_unsupported')
            except ValueError as exc:
                payload.update(success=False,export_status=res.status,status='reconstruction_failed',error_message=str(exc))
        if derive_frame_function is not None and res.success:
            try:
                payload['derived_frame_program']=res.select_frame_program(derive_frame_function,frame_data,**frame_options)
                payload['derived_frame_program']['frame_fact_intake']=frame_intake
                if not frame_program_succeeded(payload['derived_frame_program'],frame_runtime):
                    raise ValueError('ghidra_derived_frame_program_refused')
            except ValueError as exc:
                payload.update(success=False,export_status=res.status,status='derived_frame_program_failed',error_message=str(exc))
        if observe_frame_function is not None and res.success:
            try:
                payload['derived_frame_program']=res.select_observed_frame_program(observe_frame_function,
                    target_bytes=native_inputs['target_bytes'],language_sources=native_inputs['language_sources'],object_bytes=frame_object_bytes,input_receipt=native_inputs['receipt'],**frame_options)
                if not frame_program_succeeded(payload['derived_frame_program'],frame_runtime):raise ValueError('ghidra_observed_frame_program_refused')
            except ValueError as exc:
                payload.update(success=False,export_status=res.status,status='native_frame_observation_failed',error_message=str(exc)[:400])
        return payload

    @staticmethod
    def handle_webcrack(target: str, out_dir: str | None = None) -> dict[str, Any]:
        from aether_re.webcrack_bridge import WebcrackBridge
        bridge = WebcrackBridge()
        res = bridge.deobfuscate(target, output_dir=out_dir)
        return {
            "success": res.success,
            "input_path": res.input_path,
            "output_dir": res.output_dir,
            "is_bundle": res.is_bundle,
            "bundle_type": res.bundle_type,
            "module_count": res.module_count,
            "elapsed_ms": res.elapsed_ms,
            "error_message": res.error_message,
        }

    @staticmethod
    def handle_minidump_audit(target: str) -> dict[str, Any]:
        from aether_re.minidump_parser import MiniDumpParser
        parser = MiniDumpParser(target)
        return parser.audit_memory_security()

    @staticmethod
    def handle_golang_recover(target: str) -> dict[str, Any]:
        from aether_re.golang_recover import recover_golang_symbols_from_file
        return recover_golang_symbols_from_file(target)

    @staticmethod
    def handle_detect_crypto(target: str) -> dict[str, Any]:
        from aether_re.crypto_detect import scan_file_for_crypto
        return scan_file_for_crypto(target)

    @staticmethod
    def handle_audit_authenticode(target: str) -> dict[str, Any]:
        from aether_re.authenticode_audit import scan_file_authenticode
        return scan_file_authenticode(target)

    @staticmethod
    def handle_elf_dwarf_audit(target: str) -> dict[str, Any]:
        from aether_re.dwarf_types import scan_file_elf_dwarf
        return scan_file_elf_dwarf(target)

    @staticmethod
    def handle_macho_audit(target: str) -> dict[str, Any]:
        from aether_re.macho_forensics import scan_file_macho
        return scan_file_macho(target)

    @staticmethod
    def handle_rust_recover(target: str) -> dict[str, Any]:
        from aether_re.rust_recover import scan_file_rust
        return scan_file_rust(target)

    @staticmethod
    def handle_firmware_audit(target: str) -> dict[str, Any]:
        from aether_re.firmware_forensics import scan_file_firmware
        return scan_file_firmware(target)

    @staticmethod
    def handle_python_audit(target: str) -> dict[str, Any]:
        from aether_re.python_forensics import scan_file_python_artifact
        return scan_file_python_artifact(target)

    @staticmethod
    def handle_cpp_rtti(target: str) -> dict[str, Any]:
        from aether_re.cpp_rtti import scan_file_cpp_rtti
        return scan_file_cpp_rtti(target)

    @staticmethod
    def handle_api_hash_resolve(target: str) -> dict[str, Any]:
        from aether_re.api_hash_resolve import scan_file_api_hashes
        return scan_file_api_hashes(target)

    @staticmethod
    def handle_dotnet_audit(target: str) -> dict[str, Any]:
        from aether_re.dotnet_forensics import scan_file_dotnet
        return scan_file_dotnet(target)

    @staticmethod
    def handle_floss_strings(target: str) -> dict[str, Any]:
        from aether_re.floss_strings import scan_file_floss_strings
        return scan_file_floss_strings(target)

    @staticmethod
    def handle_ole_macro(target: str) -> dict[str, Any]:
        from aether_re.ole_macro import scan_file_ole_macro
        return scan_file_ole_macro(target).to_dict()

    @staticmethod
    def handle_driver_audit(target: str) -> dict[str, Any]:
        from aether_re.kernel_driver_audit import scan_file_driver_audit
        return scan_file_driver_audit(target).to_dict()

    @staticmethod
    def handle_vmlinux_carve(target: str) -> dict[str, Any]:
        from aether_re.vmlinux_extract import scan_file_vmlinux
        return scan_file_vmlinux(target).to_dict()

    @staticmethod
    def handle_dex_audit(target: str) -> dict[str, Any]:
        from aether_re.dex_forensics import scan_file_dex
        return scan_file_dex(target).to_dict()

    @staticmethod
    def handle_wasm_audit(target: str) -> dict[str, Any]:
        from aether_re.wasm_forensics import scan_file_wasm
        return scan_file_wasm(target).to_dict()

    @staticmethod
    def handle_cfi_audit(target: str) -> dict[str, Any]:
        from aether_re.cfi_gadget_audit import scan_file_cfi_audit
        return scan_file_cfi_audit(target).to_dict()

    @staticmethod
    def handle_installer_audit(target: str) -> dict[str, Any]:
        from aether_re.installer_forensics import scan_file_installer
        return scan_file_installer(target).to_dict()

    @staticmethod
    def handle_ground_truth_eval(source_c: str, decompiled_c: str, function_name: str) -> dict[str, Any]:
        from aether_re.ground_truth_eval import evaluate_decompilation_against_ground_truth
        return evaluate_decompilation_against_ground_truth(source_c, decompiled_c, function_name)


    @staticmethod
    def handle_status() -> dict[str, Any]:
        return {
            "version": __version__,
            "codename": __codename__,
            "adapters": adapters_status(),
        }

    @staticmethod
    def handle_triage(target: str) -> dict[str, Any]:
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Ficheiro alvo não encontrado: {target}")
        raw = p.read_bytes()
        ent = triage.shannon_entropy(raw[: 4 * 1024 * 1024])
        ftype = triage.detect_magic(raw[:64])
        sliding = triage.sliding_entropy(raw[: 1024 * 1024], window=4096, step=4096)
        return {
            "target": str(p.resolve()),
            "size_bytes": len(raw),
            "sha256": triage.sha256_file(p),
            "detected_format": ftype,
            "shannon_entropy": round(ent, 4),
            "is_high_entropy": ent >= 7.2,
            "sliding_entropy_sample": sliding[:10],
        }

    @staticmethod
    def handle_inspect(target: str, profile: str = "auto", shallow: bool = False) -> dict[str, Any]:
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Ficheiro alvo não encontrado: {target}")
        prof = None if profile == "auto" else profile
        report = run_megazord(p, deep=not shallow, profile_id=prof)
        return {
            "target": report.target,
            "target_sha256": report.target_sha256,
            "file_type": report.file_type,
            "size_bytes": report.size_bytes,
            "entropy": report.entropy,
            "confidence": report.overall_confidence,
            "imports_count": len(report.imports),
            "imports": [str(x) for x in report.imports[:50]],
            "exports_count": len(report.exports),
            "exports": [str(x) for x in report.exports[:50]],
            "findings_count": len(report.findings),
            "findings": [f.to_dict() if hasattr(f, "to_dict") else asdict(f) for f in report.findings[:30]],
            "functions_consensus_count": len(report.functions_consensus),
            "adapter_results": report.adapter_results,
            "limitations": report.limitations,
        }

    @staticmethod
    def handle_capabilities(target: str) -> dict[str, Any]:
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Ficheiro alvo não encontrado: {target}")
        return analyze_target_capabilities(p)

    @staticmethod
    def handle_strings_forensic(target: str, min_length: int = 5, max_count: int = 100) -> dict[str, Any]:
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Ficheiro alvo não encontrado: {target}")
        raw = p.read_bytes()
        ascii_matches = re.findall(b"[ -~]{" + str(min_length).encode() + b",}", raw)
        decoded = [m.decode("ascii", errors="replace") for m in ascii_matches[:10000]]
        categorized = _categorize_strings(decoded, max_count=max_count)
        return {
            "target": str(p.resolve()),
            "total_extracted": len(decoded),
            "categorized": categorized,
        }

    @staticmethod
    def handle_firmware_qualify(target: str, layout_file: str) -> dict[str, Any]:
        t_path = Path(target)
        l_path = Path(layout_file)
        if not t_path.is_file():
            raise FileNotFoundError(f"Blob de firmware não encontrado: {target}")
        if not l_path.is_file():
            raise FileNotFoundError(f"Ficheiro de layout não encontrado: {layout_file}")
        return qualify_firmware_layout(t_path, l_path)

    @staticmethod
    def handle_source_analyze(root_dir: str) -> dict[str, Any]:
        r_path = Path(root_dir)
        if not r_path.is_dir():
            raise NotADirectoryError(f"Diretório não encontrado: {root_dir}")
        return analyze_python_project(r_path)

    @staticmethod
    def handle_unpack(
        target: str,
        out_dir: str,
        max_files: int = 5000,
        max_bytes: int = 512 * 1024 * 1024,
    ) -> dict[str, Any]:
        from aether_re.unpackers import unpack_container
        return unpack_container(
            Path(target),
            Path(out_dir),
            max_files=max_files,
            max_bytes=max_bytes,
        )

    @staticmethod
    def handle_symbolic_explore(
        target: str,
        find_address: str | None = None,
        avoid_addresses: list[str] | None = None,
        max_steps: int = 50,
        timeout_s: int = 30,
    ) -> dict[str, Any]:
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Ficheiro alvo não encontrado: {target}")

        try:
            import angr
        except ImportError:
            return {
                "schema": "symbolic-exploration.v1",
                "status": "unavailable",
                "available": False,
                "engine": "angr",
                "target": str(p.resolve()),
                "message": "angr não está instalado no ambiente host atual. O motor simbólico é verificado no ambiente isolado venv_angr_replay_20260924_b.",
                "limitations": [
                    "exploração simbólica requer angr acoplado no runtime",
                    "postura fail-closed adotada na ausência da biblioteca",
                ],
            }

        target_sha256 = triage.sha256_file(p)
        find_addr_int = int(find_address, 16) if (isinstance(find_address, str) and find_address.strip()) else None
        avoid_addrs_int = [int(a, 16) for a in (avoid_addresses or []) if isinstance(a, str) and a.strip()]

        proj = None
        try:
            proj = angr.Project(str(p), auto_load_libs=False)
            state = proj.factory.entry_state()
            simgr = proj.factory.simulation_manager(state)

            step_count = 0
            while simgr.active and step_count < max_steps:
                simgr.step()
                step_count += 1
                if find_addr_int is not None:
                    simgr.move(from_stash="active", to_stash="found", filter_func=lambda s: s.addr == find_addr_int)
                if avoid_addrs_int:
                    simgr.move(from_stash="active", to_stash="avoid", filter_func=lambda s: s.addr in avoid_addrs_int)
                if find_addr_int and getattr(simgr, "found", None):
                    break

            found_count = len(getattr(simgr, "found", []))
            deadended_count = len(getattr(simgr, "deadended", []))
            active_count = len(getattr(simgr, "active", []))
            avoid_count = len(getattr(simgr, "avoid", []))

            status = "sat" if found_count > 0 else ("unsat" if not active_count else "bounded_cutoff")

            return {
                "schema": "symbolic-exploration.v1",
                "status": status,
                "engine": "angr",
                "target": str(p.resolve()),
                "target_sha256": target_sha256,
                "steps_executed": step_count,
                "states": {
                    "found": found_count,
                    "active": active_count,
                    "deadended": deadended_count,
                    "avoid": avoid_count,
                },
                "conclusion": "path_reachable" if found_count > 0 else ("unreachable_within_budget" if not active_count else "exploration_bounded"),
                "limitations": [
                    "exploração simbólica delimitada por cotas de passos e timeouts",
                    "não constitui prova formal irrestrita para caminhos fora do envelope de busca",
                ],
            }
        except Exception as exc:
            return {
                "schema": "symbolic-exploration.v1",
                "status": "failed",
                "engine": "angr",
                "target": str(p.resolve()),
                "target_sha256": target_sha256,
                "error": str(exc),
                "limitations": ["execução interrompida por exceção do solver"],
            }
        finally:
            if proj is not None:
                try:
                    proj.kb.rtdb.cleanup()
                except Exception:
                    pass

    @staticmethod
    def handle_binary_diff(target_a: str, target_b: str, deep: bool = False) -> dict[str, Any]:
        from aether_re.binary_diff import diff_binaries
        return diff_binaries(Path(target_a), Path(target_b), deep=deep)

    @staticmethod
    def handle_generate_yara(
        target: str,
        rule_name: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        from aether_re.forensic_rules import generate_yara_rule
        return generate_yara_rule(Path(target), rule_name=rule_name, custom_description=description)

    @staticmethod
    def handle_export_graph(
        target: str,
        output_format: str = "mermaid",
        max_nodes: int = 150,
    ) -> dict[str, Any]:
        from aether_re.graph_export import export_callgraph
        return export_callgraph(Path(target), output_format=output_format, max_nodes=max_nodes)

    @staticmethod
    def handle_function_simhash(target: str) -> dict[str, Any]:
        from aether_re.function_simhash import extract_binary_simhashes
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Arquivo não encontrado: {target}")
        profiles = extract_binary_simhashes(p)
        return {
            "schema": "function-simhash-report.v1",
            "target": str(p.resolve()),
            "total_functions": len(profiles),
            "functions": profiles,
        }

    @staticmethod
    def handle_packer_detect(target: str) -> dict[str, Any]:
        from aether_re.packer_detect import analyze_packer_and_compiler
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Arquivo não encontrado: {target}")
        return analyze_packer_and_compiler(p)

    @staticmethod
    def handle_graph_analytics(target: str, deep: bool = False, max_nodes: int = 150) -> dict[str, Any]:
        from aether_re.graph_export import _extract_callgraph_structure
        from aether_re.graph_analytics import analyze_callgraph_topology
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Arquivo não encontrado: {target}")
        nodes, edges, entry = _extract_callgraph_structure(p, deep=deep, max_nodes=max_nodes)
        return analyze_callgraph_topology(nodes, edges, entry_point=entry)

    @staticmethod
    def handle_cfg_dominance(target: str, deep: bool = False, max_nodes: int = 150) -> dict[str, Any]:
        from aether_re.graph_export import _extract_callgraph_structure
        from aether_re.cfg_dominance import analyze_cfg_structure
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Arquivo não encontrado: {target}")
        nodes, edges, entry = _extract_callgraph_structure(p, deep=deep, max_nodes=max_nodes)
        entry_point = entry or (list(nodes.keys())[0] if nodes else "entry")
        return analyze_cfg_structure(list(nodes.keys()), edges, entry_point)

    @staticmethod
    def handle_deobfuscate(expr: str) -> dict[str, Any]:
        from aether_re.deobfuscator import detect_opaque_predicate, simplify_mba_expression
        sim = simplify_mba_expression(expr)
        opq = detect_opaque_predicate(expr)
        return {"schema": "deobfuscation-report.v1", "original": expr, "simplified": sim, "opaque": opq}

    @staticmethod
    def handle_abi_infer(target: str) -> dict[str, Any]:
        from aether_re.calling_convention import infer_function_prototype
        from aether_re.engines import disasm, pe_elf, triage
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Arquivo não encontrado: {target}")
        raw = p.read_bytes()
        magic = triage.detect_magic(raw[:64])
        struct_info = pe_elf.run_structure(raw)
        dis = disasm.run_disasm(raw, is_64=struct_info.get("is_64", True), file_format=magic)
        insns = dis.get("snippets", [])
        return infer_function_prototype(insns, function_name=struct_info.get("entry_point") or "entry_point", arch="x86_64" if struct_info.get("is_64") else "x86", file_format=magic)

    @staticmethod
    def handle_taint_slice(target: str) -> dict[str, Any]:
        from aether_re.pdg_taint import compute_taint_slice
        from aether_re.engines import disasm, pe_elf, triage
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Arquivo não encontrado: {target}")
        raw = p.read_bytes()
        magic = triage.detect_magic(raw[:64])
        struct_info = pe_elf.run_structure(raw)
        dis = disasm.run_disasm(raw, is_64=struct_info.get("is_64", True), file_format=magic)
        insns = dis.get("snippets", [])
        return compute_taint_slice(insns)

    @staticmethod
    def handle_struct_recovery(target: str) -> dict[str, Any]:
        from aether_re.struct_recovery import recover_struct_layouts
        from aether_re.engines import disasm, pe_elf, triage
        p = Path(target)
        if not p.is_file():
            raise FileNotFoundError(f"Arquivo não encontrado: {target}")
        raw = p.read_bytes()
        magic = triage.detect_magic(raw[:64])
        struct_info = pe_elf.run_structure(raw)
        dis = disasm.run_disasm(raw, is_64=struct_info.get("is_64", True), file_format=magic)
        insns = dis.get("snippets", [])
        return recover_struct_layouts(insns)

    @staticmethod
    def handle_check_feasibility(constraints: str | Sequence[str]) -> dict[str, Any]:
        from aether_re.symbolic_constraints import evaluate_path_feasibility
        if isinstance(constraints, str):
            parsed_c = [c.strip() for c in re.split(r"[;,]", constraints) if c.strip()]
        else:
            parsed_c = list(constraints)
        return evaluate_path_feasibility(parsed_c)


def run_mcp_server() -> int:
    """Executa o loop stdio oficial do servidor MCP (JSON-RPC 2.0)."""
    # Configura streams binários para UTF-8 determinístico
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")

    dispatcher = AetherMcpDispatcher()

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            line_str = line.strip()
            if not line_str:
                continue

            try:
                request = json.loads(line_str)
            except json.JSONDecodeError as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
                continue

            req_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})

            # Tratamento de Handshake / Ciclo de Vida MCP
            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {
                            "tools": {},
                        },
                        "serverInfo": SERVER_INFO,
                    },
                }
            elif method == "notifications/initialized":
                # Notificação de confirmação do cliente; nenhuma resposta necessária
                continue
            elif method == "ping":
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {}}
            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": TOOLS,
                    },
                }
            elif method == "tools/call":
                tool_name = params.get("name")
                args = params.get("arguments", {})

                try:
                    if tool_name == "aether_status":
                        data = dispatcher.handle_status()
                    elif tool_name == "aether_triage":
                        data = dispatcher.handle_triage(args["target"])
                    elif tool_name == "aether_inspect":
                        data = dispatcher.handle_inspect(
                            args["target"],
                            profile=args.get("profile", "auto"),
                            shallow=args.get("shallow", False),
                        )
                    elif tool_name == "aether_detect_capabilities":
                        data = dispatcher.handle_capabilities(args["target"])
                    elif tool_name == "aether_strings_forensic":
                        data = dispatcher.handle_strings_forensic(
                            args["target"],
                            min_length=args.get("min_length", 5),
                            max_count=args.get("max_count", 100),
                        )
                    elif tool_name == "aether_firmware_qualify":
                        data = dispatcher.handle_firmware_qualify(args["target"], args["layout_file"])
                    elif tool_name == "aether_source_analyze":
                        data = dispatcher.handle_source_analyze(args["root_dir"])
                    elif tool_name == "aether_unpack":
                        data = dispatcher.handle_unpack(
                            args["target"],
                            args["out_dir"],
                            max_files=args.get("max_files", 5000),
                            max_bytes=args.get("max_bytes", 512 * 1024 * 1024),
                        )
                    elif tool_name == "aether_symbolic_explore":
                        data = dispatcher.handle_symbolic_explore(
                            args["target"],
                            find_address=args.get("find_address"),
                            avoid_addresses=args.get("avoid_addresses"),
                            max_steps=args.get("max_steps", 50),
                            timeout_s=args.get("timeout_s", 30),
                        )
                    elif tool_name == "aether_binary_diff":
                        data = dispatcher.handle_binary_diff(
                            args["target_a"],
                            args["target_b"],
                            deep=args.get("deep", False),
                        )
                    elif tool_name == "aether_generate_yara":
                        data = dispatcher.handle_generate_yara(
                            args["target"],
                            rule_name=args.get("rule_name"),
                            description=args.get("description"),
                        )
                    elif tool_name == "aether_export_graph":
                        data = dispatcher.handle_export_graph(
                            args["target"],
                            output_format=args.get("format", "mermaid"),
                            max_nodes=args.get("max_nodes", 150),
                        )
                    elif tool_name == "aether_function_simhash":
                        data = dispatcher.handle_function_simhash(args["target"])
                    elif tool_name == "aether_packer_detect":
                        data = dispatcher.handle_packer_detect(args["target"])
                    elif tool_name == "aether_graph_analytics":
                        data = dispatcher.handle_graph_analytics(
                            args["target"],
                            deep=args.get("deep", False),
                            max_nodes=args.get("max_nodes", 150),
                        )
                    elif tool_name == "aether_cfg_dominance":
                        data = dispatcher.handle_cfg_dominance(
                            args["target"],
                            deep=args.get("deep", False),
                            max_nodes=args.get("max_nodes", 150),
                        )
                    elif tool_name == "aether_deobfuscate":
                        data = dispatcher.handle_deobfuscate(args["expr"])
                    elif tool_name == "aether_abi_infer":
                        data = dispatcher.handle_abi_infer(args["target"])
                    elif tool_name == "aether_taint_slice":
                        data = dispatcher.handle_taint_slice(args["target"])
                    elif tool_name == "aether_struct_recovery":
                        data = dispatcher.handle_struct_recovery(args["target"])
                    elif tool_name == "aether_ghidra_decompile":
                        data = dispatcher.handle_ghidra_decompile(
                            args["target"],
                            type_injection=args.get("type_injection", False),
                            ir_function=args.get("ir_function"),
                            reconstruct_function=args.get("reconstruct_function"),
                            memory_model=args.get('memory_model'),
                            memory_derivation=args.get('memory_derivation'),
                            call_model=args.get('call_model'),
                            **({key:args.get(key) for key in ('derive_frame_function','frame_fact')}
                               if any(args.get(key) is not None for key in ('derive_frame_function','frame_fact')) else {}),
                            **({key:args.get(key) for key in ('observe_frame_function','frame_object_bytes','frame_language_dir')}
                               if any(args.get(key) is not None for key in ('observe_frame_function','frame_object_bytes','frame_language_dir')) else {}),
                            debug_pdb=args.get('debug_pdb'),dia_helper=args.get('dia_helper'),dia_dll=args.get('dia_dll'),
                            timeout=args.get("timeout", 300),
                            **({'ghidra_runtime_lock':args['ghidra_runtime_lock']} if args.get('ghidra_runtime_lock') is not None else {}),
                            **({'frame_runtime':args['frame_runtime']} if args.get('frame_runtime') is not None else {}),
                        )
                    elif tool_name == "aether_webcrack":
                        data = dispatcher.handle_webcrack(
                            args["target"],
                            out_dir=args.get("out_dir"),
                        )
                    elif tool_name == "aether_minidump_audit":
                        data = dispatcher.handle_minidump_audit(args["target"])
                    elif tool_name == "aether_golang_recover":
                        data = dispatcher.handle_golang_recover(args["target"])
                    elif tool_name == "aether_detect_crypto":
                        data = dispatcher.handle_detect_crypto(args["target"])
                    elif tool_name == "aether_audit_authenticode":
                        data = dispatcher.handle_audit_authenticode(args["target"])
                    elif tool_name == "aether_elf_dwarf_audit":
                        data = dispatcher.handle_elf_dwarf_audit(args["target"])
                    elif tool_name == "aether_macho_audit":
                        data = dispatcher.handle_macho_audit(args["target"])
                    elif tool_name == "aether_rust_recover":
                        data = dispatcher.handle_rust_recover(args["target"])
                    elif tool_name == "aether_firmware_audit":
                        data = dispatcher.handle_firmware_audit(args["target"])
                    elif tool_name == "aether_python_audit":
                        data = dispatcher.handle_python_audit(args["target"])
                    elif tool_name == "aether_cpp_rtti":
                        data = dispatcher.handle_cpp_rtti(args["target"])
                    elif tool_name == "aether_api_hash_resolve":
                        data = dispatcher.handle_api_hash_resolve(args["target"])
                    elif tool_name == "aether_dotnet_audit":
                        data = dispatcher.handle_dotnet_audit(args["target"])
                    elif tool_name == "aether_floss_strings":
                        data = dispatcher.handle_floss_strings(args["target"])
                    elif tool_name == "aether_ole_macro":
                        data = dispatcher.handle_ole_macro(args["target"])
                    elif tool_name == "aether_driver_audit":
                        data = dispatcher.handle_driver_audit(args["target"])
                    elif tool_name == "aether_vmlinux_carve":
                        data = dispatcher.handle_vmlinux_carve(args["target"])
                    elif tool_name == "aether_dex_audit":
                        data = dispatcher.handle_dex_audit(args["target"])
                    elif tool_name == "aether_wasm_audit":
                        data = dispatcher.handle_wasm_audit(args["target"])
                    elif tool_name == "aether_cfi_audit":
                        data = dispatcher.handle_cfi_audit(args["target"])
                    elif tool_name == "aether_installer_audit":
                        data = dispatcher.handle_installer_audit(args["target"])
                    elif tool_name == "aether_ground_truth_eval":
                        data = dispatcher.handle_ground_truth_eval(
                            args["source_c"],
                            args["decompiled_c"],
                            args["function_name"],
                        )
                    elif tool_name == "aether_check_feasibility":
                        data = dispatcher.handle_check_feasibility(args["constraints"])
                    else:
                        raise ValueError(f"Ferramenta desconhecida: {tool_name}")

                    content_text = json.dumps(data, indent=2, ensure_ascii=False)
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": content_text}],
                            "isError": False,
                        },
                    }
                except Exception as exc:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Erro na execução da ferramenta {tool_name}: {type(exc).__name__}: {exc}"}],
                            "isError": True,
                        },
                    }
            else:
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }

            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()

        except (BrokenPipeError, KeyboardInterrupt):
            break
        except Exception as exc:
            try:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": f"Internal error: {type(exc).__name__}: {exc}"},
                }
                sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
            except Exception:
                pass

    return 0

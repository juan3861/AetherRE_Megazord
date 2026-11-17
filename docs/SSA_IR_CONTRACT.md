# Contrato local de SSA — 28/10/2026

`aether_re/ssa_ir.py::lift_to_ssa_ir` constrói identidades def/use e phi por predecessor sobre um CFG fornecido. Não é lifting semântico universal de x86/ARM/bytecode, recuperação de ABI nem prova de equivalência de máquina. A construção ainda não foi integrada ao pipeline universal.

Com `cfg_edges`, cada instrução deve informar `block`. Os extremos das arestas também declaram blocos vazios. A entrada não pode ter backedge: declarar um preheader explícito. Blocos inalcançáveis são relatados e excluídos do SSA alcançável, inclusive como fontes de phi.

O passe calcula dominadores, fronteiras de dominância e inserção iterada de phi por variável. A renomeação percorre a árvore de dominância com pilhas restauradas entre irmãos. Cada fonte de phi é vinculada à definição que alcança seu predecessor; uma confluência sem definição concorrente não cria `phi_var` fictício. Valores de entrada recebem versão zero e aparecem em `live_in_values`; constantes permanecem literais. Uma cópia para o mesmo registrador lê a versão anterior à escrita.

`status=complete` e `ssa_valid=true` dizem respeito à forma SSA do subconjunto abstrato explicitado. `semantic_equivalence_proved=false` permanece sempre. Instruções não modeladas, memória, salto indireto e mistura de aliases de registradores tornam o relatório parcial, preservando a instrução bruta. Lista de operandos inválida, instrução após terminador ou contradição entre branch direto e CFG tornam o relatório inválido. `RETURN` assume leitura abstrata de `rax`, declarada em `return_register_assumption`; nenhuma ABI foi inferida.

Operações reconhecidas: mov/movzx/movsx/movsxd, formas de dois operandos add/sub/imul/and/or/xor, cmp/test, Jcc diretos, jmp direto, ret e nop. Flags são valores abstratos de dependência; predicados concretos e flags indefinidas não estão modelados. Shifts abstêm-se porque count zero pode preservar flags. Largura/overflow, memória, empilhamento, chamadas, clobbers de ABI e aliases requerem o próximo lifting semântico.

Budgets atuais: 20.000 instruções, 20.000 arestas, 1.024 blocos, 20.000 phi, operandos de até 4.096 caracteres. Não há promessa de memória constante nem de desempenho para grafos arbitrariamente densos.

Contraprovas: `tests/test_ssa_contract.py`; regressões adjacentes em `tests/test_cfg_dominance.py` e `tests/test_six_gears.py`. Revisão interna inclui comparação de idom com NetworkX e invariantes de dominância/def-use em CFGs determinísticos. Essas verificações não substituem corpus independente, diferencial executado em laboratório, integração E2E ou homologação F00–F12.

# Exportação estática Ghidra — contrato v2

O produtor `aether_re/ghidra_scripts/DecompileAllFunctions.java` e a bridge `aether_re/ghidra_headless_bridge.py` usam `aetherre-ghidra-export.v2`. Este contrato identifica e inventaria uma exportação estática; não certifica correção de descompilação, equivalência binária, recuperação de tipos ou código-fonte original.

## Identidade, inventário e fontes

O hash SHA-256 do arquivo importado é obtido pelo programa Ghidra e deve coincidir com o snapshot da entrada feito pela bridge. A função é identificada por `target_sha256!address_space:hex_offset`, com offset normalizado. Nomes são metadados: funções homônimas permanecem distintas.

`GhidraDecompilationResult.functions` agora é indexado por essa identidade. Consumidores antigos que indexavam por nome devem usar `get_unique_function(name)` para resolver somente um candidato. Ausência ou ambiguidade retorna `None`, sem escolha arbitrária. O endereço é o endereço do programa analisado, não prova de endereço runtime após ASLR.

O JSON contém o inventário por endereço, sucesso/falha e contagens reconciliadas. Cada sucesso exige um arquivo C individual não vazio. P-Code textual, quando disponível, possui arquivo próprio. A associação não depende de regex de headers em C nem de nomes. O consumidor confere schema, hash, tipos dos campos, endereços duplicados, contagens, arquivos referenciados e ausência de sobras inesperadas. JSON com chaves duplicadas ou UTF-8 inválido é recusado.

`status=complete` / `success=true` exigem inventário finalizado, não vazio e todas as funções do inventário exportadas com fonte. `status=partial` mantém inventário e fontes válidas quando há falhas, cancelamento ou orçamento de exportação incompleto; `success=false`. Artefato inválido, worker falho ou contrato não reconciliado retorna `status=failed`, sem publicar funções como válidas. Uma contagem de exportação nunca mede precisão semântica.

## Tipos observados e opção legada

Nenhum desses produtores injeta estruturas cJSON, tamanhos de ponteiro ou endereços fixos. `DecompileWithTypeInjection.java` é uma entrada legada que usa o mesmo exportador e marca `legacy_type_injection_requested=true`. Ela não altera o programa com hipóteses cJSON.

`type_policy` declara `mode=observed_program_types`, `external_types_injected=false` e `type_recovery_proved=false`. O validador rejeita flags que afirmem recuperação ou injeção nesse contrato. Cada função informa assinatura observada e `signature_source` do Ghidra (`DEFAULT`, `ANALYSIS`, `IMPORTED` ou `USER_DEFINED`). Esses rótulos não provam, por si, origem DWARF/PDB exata, layout de structs ou correção de ABI. Recuperação real de tipos com identidade/proveniência continua pendente.

O MCP usa o caminho sem opção legada por padrão. O argumento antigo `type_injection` e a flag CLI `--type-injection` permanecem reconhecidos, com descrição explícita de que não injetam hipóteses. CLI/MCP expõem estado, política de tipos, nome e identidade de função, contagem retornada e indicador de recorte (50 funções na CLI, 30 no MCP). O recorte de apresentação não altera o denominador da exportação.

## Recursos e publicação

O worker usa Java direto e contenção de árvore requerida, memória e tempo limitados, stdout/stderr capturados com teto e diretórios privados. Entrada: no máximo 512 MiB. Os dois scripts Java são capturados em arquivos privados, até 1 MiB por script; hashes ficam em `worker_execution.producer_sha256`. O postscript lê esses snapshots, não a pasta de fontes compartilhada durante uma chamada longa.

Orçamentos do produtor: 50.000 funções, 2 MiB por arquivo C/P-Code, 56 MiB acumulados de payload e 8 MiB de summary. Escritas UTF-8 e create-only. O consumidor limita a árvore de artefatos a 64 MiB e reconfere limites antes de ler, inclusive sob produtor adulterado. Symlinks, reparse points, hardlinks, arquivos não regulares, caminhos externos, fontes reutilizadas e arquivos não referenciados são recusados. Não é WORM nem proteção contra um administrador que controla o host.

A CLI só publica `--out` quando a exportação é completa. Falha/parcial imprime o relatório e retorna erro, preservando qualquer destino anterior. Sucesso usa o protocolo existente `create_verified_snapshot`: staging, hash, fsync e publicação atômica sem sobrescrita. Destino existente também retorna erro. Chamadores que precisam examinar resultados parciais podem usar a API e preservar explicitamente seus metadados; não há promoção automática a fonte completa.

## Provas e fronteiras

As contraprovas do lote 05 cobrem homônimos, fontes ausentes, contagens contraditórias, schema/hash incorretos, paths externos, identidade duplicada, limites, hardlinks, flags de prova forjadas, captura de scripts e preservação de saída CLI em falha/sucesso. Há testes de consumidores CLI/MCP e de demonstrador que mantém comparação comportamental inconclusiva sem convertê-la em aprovação por score estrutural.

Smokes reais usam um DLL próprio benigno de três exports, compilado apenas para leitura estática. O binário não é executado. O smoke também mostra uma fronteira: Ghidra pode inferir `byte` para um retorno declarado `int` na fonte, portanto exportar assinatura não quita tipos/ABI. Não houve boot de VM, trace do alvo, equivalência binária ou revisão humana independente. Evidência em `C:/Users/juanp/Documents/Codex/audits/aetherre-20261028/implementation-05/` e revisão interna em `review-05/`.

O lote 06 acrescenta arquivos High P-Code estruturados opcionais e projeção no IR existente, conforme `docs/GHIDRA_PCODE_IR_CONTRACT.md`. Exportações v2 anteriores sem IR permanecem aceitas e aparecem como IR indisponível; não recebem grafo inventado. Permanece necessário modelar semântica de máquina, memória, flags e ABI, integrar SSA/C-Tree/pipeline e validar em corpus e laboratório independentes. O contrato não apresenta esse export como lifting completo.

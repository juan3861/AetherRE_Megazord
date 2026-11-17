# Memória explícita na reconstrução High P-Code

`reconstruct_high_pcode(..., memory_model='bounded-bytes.v1')` habilita LOAD/STORE em um único espaço de memória byte-addressable. Sem esta opção, o transporte escalar mantém a abstenção para operações de memória.

O C emitido recebe `struct aether_memory *aether_memory` antes dos parâmetros escalares. O chamador fornece armazenamento C válido, não sobreposto, para estado, bytes, permissões, inicialização e eventos. Endereços abstratos nunca são convertidos em ponteiros do host. Esta hipótese não recupera mapa de processo, parâmetros originais nem ABI.

O modelo admite larguras 1/2/4/8 e respeita endian do IR. STORE verifica todos os bytes e a capacidade de trace antes de alterar memória. LOAD exige bytes inicializados e permissão de leitura. Sobreposição de endereços usa os mesmos bytes; não há buffers independentes por variável.

Limites: região até 1 MiB, até 4096 eventos, até 1 milhão de passos. Cada operação P-Code consome um passo; visitar um bloco original vazio também consome um passo para conter ciclos sem operações. O limite de expansão do CFG permanece independente. Espaços múltiplos, word_size diferente de 1, selector não representável, chamadas e armazenamento persistente sem modelo são recusados.

Status do estado: 0 sucesso, 1 estado inválido, 2 passos esgotados, 3 espaço incompatível, 4 fora da região, 5 permissão, 6 não inicializado, 7 trace esgotado. Retorno só é válido com status 0. O estado e os eventos preservam os efeitos anteriores à falha; não há rollback de função inteira. Um ponteiro de estado nulo viola o contrato do chamador.

CLI: `ghidra-decompile ALVO --reconstruct-function FUNCAO --memory-model bounded-bytes.v1`. MCP: `aether_ghidra_decompile` com `reconstruct_function` e `memory_model`. Universal: `--native-reconstruction --native-memory-model bounded-bytes.v1`. Configuração inválida é recusada antes do backend/intake. Adaptador opcional de retorno DIA preserva o parâmetro de estado e seus status; não resolve ABI de entrada.

Pseudo-fonte não é código-fonte original. Comparação de C gerado contra oráculo de bytes é evidência de um subconjunto finito sob hipótese explícita. Mesmo uma exportação real Ghidra não prova equivalência com o binário nem quita corpus externo, holdout, laboratório VM, revisão humana independente ou custódia WORM.

## Núcleo esparso experimental — bounded-bytes.v2

O lowerer também admite explicitamente `memory_model='bounded-bytes.v2'` na API Python. Ele emite `struct aether_sparse_memory` e helpers próprios, preservando os tipos e a saída de v1. A integração v2 nas opções CLI/MCP/universal ainda não está concluída; essas interfaces continuam expondo somente v1 neste checkpoint.

O estado v2 recebe tabela de0..128regiões ordenadas e sem sobreposição, cada uma com base/tamanho e buffers bytes/perms/init válidos e estáveis durante a chamada. A soma é limitada a1MiB; lacunas virtuais não são alocadas. Busca por endereço usa a tabela, sem converter VA em ponteiro. Acesso de1/2/4/8bytes pode atravessar regiões adjacentes. Todos os bytes e capacidade de evento são verificados antes de STORE, de modo que uma operação falha não escreve parcialmente. Efeitos de operações anteriores continuam preservados. Status, passos e guards de blocos vazios mantêm o contrato v1.

Prova inicial v2:16variantes×43cenários×Od/O2=1376observações sem divergências contra oráculo independente de dicionário de endereços. Trata-se de IR sintético próprio, não equivalência de um binário real. Comparação finita de28funções de exports PE/ELF confirmou C e campos de contrato v1 idênticos ao lowerer anterior; runtimeC v1 também idêntico em bytes. Isso não substitui regressão integral após a alteração.

O ELF real observado possui funções LOAD/STORE traduzíveis, mas sua base de análise Ghidra é0x100000 e a base de link do mapa é0. Qualquer integração precisa registrar a transformação de endereços e sua proveniência. Não aplicar slide silenciosamente nem chamar esse mapa de snapshot capturado. Revisão independente atual e demais requisitos globais continuam pendentes.

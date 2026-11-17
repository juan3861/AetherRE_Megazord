# Derivações de memória no kernel — execução12

`publish_memory_derivation(case_dir, destination, profile='pe'|'elf', space_id=..., sparse=False)` lê um intake existente cuja custódia e journal sejam válidos. O destino deve ser novo, fora da árvore do caso e com reserva de disco. Os arquivos do intake permanecem inalterados.

A derivação usa EvidenceStore e EvidenceJournal existentes numa árvore separada. Publica cópia hash-verificada do input, bytes/permissões/inicialização por região, relatório canônico e DerivationRecord HYPOTHESIS com pais e método. A conclusão só é devolvida após manifesto, evento de conclusão, recibo local e verificação pós-publicação. Interrupções deixam evidência parcial e nunca um resultado complete válido.

Os dois fingerprints de autorização do kernel são respeitados: manifesto usa a representação pública da política; ArtifactRef usa o dataclass normalizado. A integração confere ambos, preservando o formato vigente do EvidenceStore. Autorizações dinâmicas não são inferidas nem usadas para executar o alvo.

`verify_memory_derivation(directory)` confere custódia local, hash-chain e eventos de publicação/conclusão, refs e autorização; refaz o mapa dos bytes de entrada e compara metadados e buffers. Journal, manifesto, head e receipt têm limites antes de hash/parsing. Links e objetos com múltiplos hardlinks são recusados. A verificação não autentica a origem por terceiro nem prova verdade universal do algoritmo.

`replay_memory_derivation(directory, destination)` cria novo intake e derivação a partir do input guardado. O SHA256 do relatório canônico precisa coincidir, e o resultado é verificado novamente. A prova atual é replay local da derivação com a mesma implementação e autorização; não é instalação hermética, replay integral da ferramenta ou WORM. Recibos locais vinculam caminhos: relocação física exige procedimento próprio, não cópia arbitrária do diretório.

`bind_memory_derivation(directory, target_sha256=..., space_id=..., image_base=..., bits=..., endian=...)` exige contexto tipado e correspondência integral antes de devolver a referência e os metadados. Não aplica slide ELF, não converte endereços em ponteiros e não inicializa runtime automaticamente. Sparse preserva `contiguous_runtime_compatible=false`.

Provas atuais: intakes PE próprio e ELF instalado preservados; publicação/recomputação/replay com mesmos hashes; contexto correto aceito e alvo diferente recusado; testes de adulteração, falha parcial e orçamento. Ainda faltam referências de mapa nos fluxos CLI/MCP/universal, runtime esparso, revisão independente atual e regressão/selo completos12. `process_snapshot_proved=false`, sem gates promovidos. Pseudo-fonte não é fonte original.

## Referências nas interfaces

CLI Ghidra: `--memory-model bounded-bytes.v1 --memory-derivation BUNDLE --reconstruct-function FUNCAO`. MCP: parâmetros memory_model, memory_derivation e reconstruct_function. Universal: `--native-reconstruction --native-memory-model bounded-bytes.v1 --native-memory-derivation BUNDLE`.

Configuração e identidade do alvo são verificadas antes do backend. A admissão do bundle produz um contexto imutável interno de snapshot; recibo e manifesto devem permanecer idênticos durante a verificação. O fluxo universal admite uma vez por caso. Um dict recebido de JSON não pode substituir esse contexto. Por função, a ponte exige namespace de imagem/espaço coerente, ID Ghidra normalizado em uint32, base, bits e endian correspondentes ao IR.

`memory_binding` contém referência e resumo do contexto com `admission_scope=verified_bundle_snapshot`. Ele registra o instante de admissão e não afirma que os arquivos continuarão íntegros. Leitura posterior de buffers/replay deve verificar os hashes no EvidenceStore. A seleção não executa o alvo nem inicializa memória do host. Funções não traduzíveis mantêm IR e binding indisponível. O adaptador de retorno DIA preserva o binding quando disponível.

O runtime11 continua contíguo: mapas sparse solicitados para essa reconstrução são recusados explicitamente. O suporte esparso ainda é pendência. Correção da lista anterior: as opções nas interfaces estão implementadas; suas provas reais e regressão após alteração são separadas da regressão de1361testes anterior à mudança. A primeira chamada real recusou o bundle espaço0, pois o IR real observava ram.id433; a derivação foi refeita explicitamente a partir dessa observação, sem afrouxar a correspondência.

## V2 e endereçamento de análise ELF

As interfaces agora aceitam bounded-bytes.v2 explicitamente. Bundles sparse continuam recusados por v1 e recebem `runtime_compatible=true` somente quando escolhida v2; `contiguous_runtime_compatible=false` permanece preservado. A escolha não executa ou inicializa o estado C automaticamente.

`build_elf_memory` e `publish_memory_derivation` aceitam `analysis_base` opcional, somente para ELF. A transformação valida inteiros e o intervalo de todas as regiões na largura observada. Mantém bytes, permissões e desconhecidos; registra `analysis_addressing` com base de link, base de análise e bias. Cada região guarda também link_address. Base declarada é hipótese de análise, não endereço observado num processo. Unknown ranges continuam relativos à base correspondente.

Quando fornecida, analysis_base fica no manifesto da derivação, participa do produto canônico e é usada na recomputação e no replay. Bundles anteriores sem a opção mantêm o contrato anterior. O resumo de admissão e o binding expõem a transformação. Nenhum slide é aplicado de forma invisível na ponte.

No ELF instalado, o IR observado define ram.id433/image_base0x100000; o mapa de link começa em0. A nova derivação é criada com essa base explícita e vinculada ao hash do export usado como evidência. Ainda exige provas reais separadas e não resolve ABI, loader, dependências ou snapshot de processo.

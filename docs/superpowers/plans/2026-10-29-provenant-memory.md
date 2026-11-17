# Memória com proveniência — execução12

Objetivo integral permanece o auditor forense avançado da planta-mãe. Este plano cobre a dependência seguinte à reconstrução bounded-bytes.v1; não redefine conclusão do projeto.

Design e alternativas: implementation-11/NEXT_ACTION_12.md no diretório de auditoria. Reaproveitar kernel de evidência e runtime, sem nova engine paralela. O grafo aponta aether_re.engines.pe_elf.run_structure como observador existente de segmentos; sua tolerância não o qualifica como loader estrito.

1. Criar tests/test_native_memory_map.py e API aether_re/native_memory.py: build_file_memory(data, *, target_sha256, base, space_id, regions). Contrato de regiões declaradas com address/file_offset/file_size/memory_size/permissions/zero_fill. Hash deve corresponder aos mesmos bytes. Validar tipos exatos, overflow, intervalos, overlaps, limites e extensão total antes de alocar. Lacunas sem permissão e não inicializadas; file bytes com origem; tail só inicializado por hipótese explícita zero_fill. Retorno não pode alegar memória real de processo. Rodar RED e implementar mínimo correto; revisão focal do contrato.
2. Adicionar derivação PE/ELF estrita a partir dos bytes admitidos, com machine/endian/base observados. Usar parser existente para observações e verificar fronteiras independentemente. Reloc/import não resolvidos invalidam células afetadas para execução semântica. Testes com fonte própria e layouts conhecidos; nenhum nome de seção vira autoridade.
3. Publicar derivação no EvidenceStore create-only e bindar target/context/spaces/image_base. Alimentar runtime11 com bytes/perms/init; ampliar para múltiplos intervalos somente com limites e testes de lacunas. CLI/MCP/universal exigem opção/ref explícita com custódia.
4. Diferencial real fonte-build-IR-C sobre mapa observado e corpus de layouts malformados; registrar falhas e limites. Depois integrar snapshot capturado de laboratório, chamadas/ABI e traces. Snapshot exige boot/nonce/identidade/trace/restore; imagem preferida estática não é snapshot.

Critérios: nenhum byte inicializado sem proveniência; nenhuma lacuna promovida; recusa anterior à alocação excessiva; toda derivação vinculada ao hash; reportar hipóteses e denominadores. Suíte/receipts/revisão interna não quitam corpus externo/holdout, WORM, replay hermético ou revisão humana.

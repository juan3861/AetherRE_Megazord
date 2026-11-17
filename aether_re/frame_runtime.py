"""Trusted descriptor scope for an explicitly derived C frame program.

Caller runtime metadata and buffers must be valid and nonaliasing. This is not
pointer provenance, callback fencing or a native call-frame allocator.
"""
FRAME_RUNTIME = r'''
struct aether_frame_scope {
    struct aether_sparse_memory *memory;
    struct aether_sparse_region *saved;
    unsigned long long saved_count;
    struct aether_sparse_region table[128];
    unsigned int active;
};
static int aether_frame_enter(struct aether_frame_scope *scope,
    struct aether_sparse_memory *memory, unsigned long long base,
    unsigned long long length, unsigned char *bytes,
    unsigned char *permissions, unsigned char *initialized) {
    struct aether_sparse_memory candidate;
    struct aether_sparse_region table[128], region;
    unsigned long long n, pos=0ULL, k, end;
    if (!scope || !memory || scope->active || !length || (base&15ULL) ||
        !bytes || !permissions || !initialized || length-1ULL>ULLONG_MAX-base ||
        memory->region_count>=128ULL) return 0;
    candidate=*memory;
    if (!aether_sparse_memory_valid(&candidate, ULLONG_MAX)) return 0;
    n=memory->region_count; end=base+length-1ULL;
    for(k=0ULL;k<n;++k) {
        struct aether_sparse_region *r=&memory->regions[k];
        if(base<=r->base+r->length-1ULL && r->base<=end) return 0;
        if(r->base<base) ++pos;
    }
    region=(struct aether_sparse_region){bytes,permissions,initialized,base,length};
    for(k=0ULL;k<pos;++k) table[k]=memory->regions[k];
    table[pos]=region;
    for(k=pos;k<n;++k) table[k+1ULL]=memory->regions[k];
    candidate.regions=table; candidate.region_count=n+1ULL;
    if(!aether_sparse_memory_valid(&candidate, ULLONG_MAX)) return 0;
    scope->memory=memory; scope->saved=memory->regions; scope->saved_count=n;
    for(k=0ULL;k<=n;++k) scope->table[k]=table[k];
    scope->active=1U; memory->regions=scope->table; memory->region_count=n+1ULL;
    return 1;
}
static int aether_frame_leave(struct aether_frame_scope *scope) {
    struct aether_sparse_memory *memory;
    if(!scope || !scope->active || !scope->memory) return 0;
    memory=scope->memory;
    if(memory->regions!=scope->table || memory->region_count!=scope->saved_count+1ULL) return 0;
    memory->regions=scope->saved; memory->region_count=scope->saved_count;
    scope->active=0U; scope->memory=0; scope->saved=0; scope->saved_count=0ULL;
    return 1;
}
'''

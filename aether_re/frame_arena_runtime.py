"""Scoped logical arenas for derived models, under valid nonaliasing C metadata.

Descriptor shape checks are not a sandbox or arbitrary pointer provenance.
Context/scope bookkeeping itself remains trusted caller-owned storage.
"""
from .frame_runtime import FRAME_RUNTIME

FRAME_ARENA_RUNTIME=FRAME_RUNTIME+r'''
struct aether_arena_scope;
struct aether_arena_context {
    struct aether_sparse_memory *memory;
    unsigned long long base, span, next_token, depth;
    struct aether_arena_scope *top;
};
struct aether_arena_scope {
    struct aether_frame_scope frame;
    struct aether_arena_context *arena;
    struct aether_arena_scope *parent;
    struct aether_sparse_region expected[128];
    struct aether_sparse_event *events;
    unsigned long long base, token, position, arena_base, arena_span, space_id, event_capacity;
};
static int aether_arena_fail(struct aether_arena_context *a) {
    if(a && a->memory && !a->memory->status)a->memory->status=1U;
    return 0;
}
static int aether_arena_geometry(unsigned long long base,unsigned long long span) {
    return !(base&15ULL) && span && span<=4096ULL && span-1ULL<=ULLONG_MAX-base;
}
static int aether_arena_same(struct aether_sparse_region *a,struct aether_sparse_region *b) {
    return a->bytes==b->bytes && a->permissions==b->permissions &&
        a->initialized==b->initialized && a->base==b->base && a->length==b->length;
}
static int aether_arena_intact(struct aether_arena_scope *s) {
    struct aether_sparse_memory *m;
    unsigned long long k,n,index;
    if(!s || !s->arena || !s->frame.active || !s->token)return 0;
    m=s->frame.memory;n=s->frame.saved_count;
    if(!m || m!=s->arena->memory || n>=128ULL || s->position>n ||
       m->regions!=s->frame.table || m->region_count!=n+1ULL ||
       s->arena->base!=s->arena_base || s->arena->span!=s->arena_span ||
       m->space_id!=s->space_id || m->events!=s->events ||
       m->event_capacity!=s->event_capacity || m->event_count>m->event_capacity ||
       m->steps_executed>1000000ULL || m->steps_left>1000000ULL-m->steps_executed)return 0;
    for(k=0ULL;k<=n;++k)if(!aether_arena_same(&m->regions[k],&s->expected[k]))return 0;
    for(k=0ULL;k<n;++k) {
        index=k<s->position?k:k+1ULL;
        if(!aether_arena_same(&s->frame.saved[k],&s->expected[index]))return 0;
    }
    return 1;
}
static int aether_arena_init(struct aether_arena_context *a,
    struct aether_sparse_memory *m,unsigned long long base,unsigned long long span) {
    if(!a || !m || a->memory || a->top || a->depth || a->next_token ||
       !aether_arena_geometry(base,span))return 0;
    if(!aether_sparse_memory_valid(m,ULLONG_MAX))return 0;
    a->memory=m;a->base=base;a->span=span;a->next_token=1ULL;return 1;
}
static int aether_arena_enter(struct aether_arena_context *a,
    struct aether_arena_scope *s,unsigned long long size,unsigned char *bytes,
    unsigned char *permissions,unsigned char *initialized) {
    struct aether_sparse_memory *m;
    unsigned long long candidate,end,k,re,next,position=0ULL;
    if(!a || !s || !a->memory)return 0;
    m=a->memory;
    if(s->frame.active || s->arena || !size || size>4096ULL ||
       !aether_arena_geometry(a->base,a->span) || !a->next_token ||
       a->next_token==ULLONG_MAX || a->depth>=16ULL ||
       (!a->depth)!=(!a->top))return aether_arena_fail(a);
    if(a->top && (a->top->arena!=a || !aether_arena_intact(a->top)))return aether_arena_fail(a);
    if(!aether_sparse_memory_valid(m,ULLONG_MAX) || m->region_count>=128ULL)return aether_arena_fail(a);
    candidate=a->base;end=a->base+a->span-1ULL;
    while(candidate<=end && size-1ULL<=end-candidate) {
        next=candidate;
        for(k=0ULL;k<m->region_count;++k) {
            re=m->regions[k].base+m->regions[k].length-1ULL;
            if(candidate<=re && m->regions[k].base<=candidate+size-1ULL) {
                if((re|15ULL)==ULLONG_MAX)return aether_arena_fail(a);
                next=(re|15ULL)+1ULL;break;
            }
        }
        if(next==candidate)break;
        candidate=next;
    }
    if(candidate>end || size-1ULL>end-candidate)return aether_arena_fail(a);
    for(k=0ULL;k<m->region_count;++k)if(m->regions[k].base<candidate)++position;
    if(!aether_frame_enter(&s->frame,m,candidate,size,bytes,permissions,initialized))return aether_arena_fail(a);
    s->arena=a;s->parent=a->top;s->base=candidate;s->token=a->next_token++;
    s->position=position;s->arena_base=a->base;s->arena_span=a->span;
    s->space_id=m->space_id;s->events=m->events;s->event_capacity=m->event_capacity;
    for(k=0ULL;k<m->region_count;++k)s->expected[k]=m->regions[k];
    a->top=s;++a->depth;return 1;
}
static int aether_arena_leave(struct aether_arena_context *a,
    struct aether_arena_scope *s,unsigned long long token) {
    struct aether_sparse_memory *m;int intact;
    if(!a || !s || !a->memory)return 0;
    if(a->top!=s || s->arena!=a || !a->depth || !s->frame.active ||
       !token || token!=s->token)return aether_arena_fail(a);
    m=a->memory;intact=aether_arena_intact(s);
    /* Correct top/token always unwinds even on a failed descriptor fence. */
    m->regions=s->frame.saved;m->region_count=s->frame.saved_count;
    m->space_id=s->space_id;m->events=s->events;m->event_capacity=s->event_capacity;
    a->base=s->arena_base;a->span=s->arena_span;a->top=s->parent;--a->depth;
    s->frame.active=0U;s->frame.memory=0;s->frame.saved=0;s->frame.saved_count=0ULL;
    s->arena=0;s->parent=0;s->token=0ULL;
    if(!intact)return aether_arena_fail(a);
    return 1;
}
'''

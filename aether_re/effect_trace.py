"""Bounded operation-start history for the conditional direct-effects model.

Requires the existing sparse-memory/call runtime definitions before this C.
Host buffers and poll infrastructure remain trusted caller preconditions.
"""

EFFECT_RUNTIME = r'''
struct aether_effect_event {
    unsigned long long step, function, operation, kind;
    unsigned long long memory_events_before, call_events_before;
};
struct aether_effect_trace {
    struct aether_effect_event *events;
    unsigned long long event_capacity, event_count, last_step, context[4];
    unsigned int status, context_bound;
};
static int aether_effect_trace_shape(struct aether_effect_trace *e) {
    if(!e) return 0;
    if(e->event_capacity>1000000ULL || e->event_count>e->event_capacity ||
       (e->event_capacity && !e->events) || e->last_step>1000000ULL ||
       e->event_count!=e->last_step || e->context_bound>1U || e->status>2U) {
        e->status=1U;return 0;
    }
    return !e->status;
}
static int aether_effect_trace_states(struct aether_effect_trace *e,
    struct aether_sparse_memory *m,struct aether_call_trace *c) {
    if(!e) {if(c && !c->status)c->status=1U;return 0;}
    if(!aether_effect_trace_shape(e))return 0;
    if(!m || !aether_call_shape(c) || m->status || c->status || !c->context_bound ||
       m->steps_executed>1000000ULL || m->steps_left>1000000ULL-m->steps_executed ||
       m->event_capacity>4096ULL || m->event_count>m->event_capacity) {
        e->status=1U;return 0;
    }
    return 1;
}
static int aether_effect_trace_context(struct aether_effect_trace *e,
    struct aether_call_trace *c) {
    unsigned int i;
    if(!e->context_bound) {e->status=1U;return 0;}
    for(i=0U;i<4U;++i)if(e->context[i]!=c->context[i]) {e->status=1U;return 0;}
    return 1;
}
static int aether_effect_trace_entry(struct aether_effect_trace *e,
    struct aether_sparse_memory *m,struct aether_call_trace *c,unsigned int root) {
    unsigned int i;
    if(!aether_effect_trace_states(e,m,c))return 0;
    if(root) {
        if(e->context_bound || e->event_count || m->steps_executed || m->event_count || c->depth || c->calls || c->event_count) {
            e->status=1U;return 0;
        }
        for(i=0U;i<4U;++i)if(e->context[i]) {e->status=1U;return 0;}
        for(i=0U;i<4U;++i)e->context[i]=c->context[i];
        e->context_bound=1U;
        return 1;
    }
    if(!c->depth || !e->event_count || e->last_step!=m->steps_executed) {e->status=1U;return 0;}
    return aether_effect_trace_context(e,c);
}
static int aether_effect_trace_append(struct aether_effect_trace *e,
    struct aether_sparse_memory *m,struct aether_call_trace *c,
    unsigned long long function,unsigned long long operation,unsigned long long kind) {
    struct aether_effect_event *event;
    if(!aether_effect_trace_states(e,m,c) || !aether_effect_trace_context(e,c))return 0;
    if(e->last_step+1ULL!=m->steps_executed || function>=32ULL ||
       (kind!=1ULL && kind!=2ULL) || (kind==1ULL && operation>=900ULL) ||
       (kind==2ULL && operation>=512ULL)) {e->status=1U;return 0;}
    if(e->event_count>=e->event_capacity) {e->status=2U;return 0;}
    event=&e->events[e->event_count++];event->step=m->steps_executed;
    event->function=function;event->operation=operation;event->kind=kind;
    event->memory_events_before=m->event_count;event->call_events_before=c->event_count;
    e->last_step=m->steps_executed;
    return 1;
}
static int aether_effect_call_finish(struct aether_call_trace *c,
    struct aether_effect_trace *e,unsigned long long caller,unsigned long long callee,
    unsigned long long operation,unsigned long long memory_status,unsigned long long value) {
    if(!e || !aether_effect_trace_shape(e) || !c || !aether_effect_trace_context(e,c)) {
        if(c && !c->status)c->status=1U;
    }
    return aether_call_leave(c,caller,callee,operation,memory_status,value);
}
'''

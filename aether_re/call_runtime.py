"""Trusted-runtime call trace for the conditional direct-call C model."""

CALL_RUNTIME = r'''
struct aether_call_event {
    unsigned long long caller, callee, operation, kind, memory_status, value;
    unsigned long long argument_count, arguments[64];
};
struct aether_call_trace {
    struct aether_call_event *events;
    unsigned long long event_capacity, event_count, depth, depth_limit, calls, call_limit;
    unsigned long long context[4];
    unsigned int status, context_bound;
    int (*poll)(void *);
    void *poll_context;
};
static int aether_call_shape(struct aether_call_trace *c) {
    if (!c) return 0;
    if (c->event_capacity>4096ULL || c->event_count>c->event_capacity ||
        (c->event_capacity && !c->events) || c->depth_limit>16ULL ||
        c->depth>c->depth_limit || c->call_limit>1000000ULL || c->calls>c->call_limit || c->context_bound>1U) {
        c->status=1U; return 0;
    }
    return 1;
}
static int aether_call_entry(struct aether_call_trace *c, unsigned int root,
    unsigned long long a, unsigned long long b, unsigned long long d, unsigned long long e) {
    unsigned long long expected[4]={a,b,d,e}; unsigned int i;
    if (!aether_call_shape(c) || c->status) return 0;
    if ((root && c->depth) || (!root && !c->depth)) { c->status=1U; return 0; }
    if (!c->context_bound) {
        if (!root || c->calls || c->event_count) { c->status=1U; return 0; }
        for(i=0U;i<4U;++i)if(c->context[i]) { c->status=1U; return 0; }
        for(i=0U;i<4U;++i)c->context[i]=expected[i];
        c->context_bound=1U;
    } else {
        for(i=0U;i<4U;++i)if(c->context[i]!=expected[i]) { c->status=1U; return 0; }
    }
    return 1;
}
static int aether_call_tick(struct aether_call_trace *c) {
    int stop;
    if (!aether_call_shape(c) || c->status) return 0;
    if (c->poll) {
        stop=c->poll(c->poll_context);
        if (stop) { c->status=stop==1 ? 5U : stop==2 ? 6U : 1U; return 0; }
    }
    return aether_call_shape(c) && !c->status;
}
static int aether_call_enter(struct aether_call_trace *c, unsigned long long caller,
    unsigned long long callee, unsigned long long operation,
    const unsigned long long *arguments, unsigned long long argument_count) {
    struct aether_call_event *event; unsigned long long i;
    if (!aether_call_shape(c) || c->status) return 0;
    if (argument_count>64ULL || (argument_count && !arguments)) { c->status=1U; return 0; }
    if (c->depth>=c->depth_limit) { c->status=2U; return 0; }
    if (c->calls>=c->call_limit) { c->status=4U; return 0; }
    if (c->event_count>=c->event_capacity) { c->status=3U; return 0; }
    event=&c->events[c->event_count++];
    event->caller=caller;event->callee=callee;event->operation=operation;
    event->kind=1ULL;event->memory_status=0ULL;event->value=0ULL;
    event->argument_count=argument_count;
    for(i=0ULL;i<64ULL;++i)event->arguments[i]=i<argument_count ? arguments[i] : 0ULL;
    ++c->depth;++c->calls;return 1;
}
static int aether_call_leave(struct aether_call_trace *c, unsigned long long caller,
    unsigned long long callee, unsigned long long operation,
    unsigned long long memory_status, unsigned long long value) {
    struct aether_call_event *event; unsigned long long i;
    if (!aether_call_shape(c)) return 0;
    if (!c->depth) { c->status=1U; return 0; }
    --c->depth;
    if (c->status) return 0;
    if (c->event_count>=c->event_capacity) { c->status=3U; return 0; }
    event=&c->events[c->event_count++];
    event->caller=caller;event->callee=callee;event->operation=operation;
    event->kind=2ULL;event->memory_status=memory_status;event->value=value;
    event->argument_count=0ULL;
    for(i=0ULL;i<64ULL;++i)event->arguments[i]=0ULL;
    return memory_status==0ULL;
}
'''

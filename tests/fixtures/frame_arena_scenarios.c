#define CHECK(c) do { if(!(c)) return __LINE__; } while(0)
static void arena_zero(void *ptr,unsigned long long size) {
    unsigned char *p=(unsigned char*)ptr;unsigned long long i;
    for(i=0;i<size;++i)p[i]=0;
}
__declspec(dllexport) unsigned int arena_scenario(unsigned int mode) {
    struct aether_sparse_memory memory;
    struct aether_sparse_event events[8];
    struct aether_sparse_region original;
    struct aether_arena_context arena;
    struct aether_arena_scope scopes[17];
    unsigned char ambient[16],perms[16],init[16],bytes[17][16],permissions[17][16],initialized[17][16];
    unsigned long long i,j,t0,t1;
    arena_zero(&memory,sizeof(memory));arena_zero(&arena,sizeof(arena));arena_zero(scopes,sizeof(scopes));
    arena_zero(ambient,sizeof(ambient));arena_zero(init,sizeof(init));
    arena_zero(bytes,sizeof(bytes));arena_zero(initialized,sizeof(initialized));
    for(i=0;i<16;++i)perms[i]=3;
    for(i=0;i<17;++i)for(j=0;j<16;++j)permissions[i][j]=3;
    original=(struct aether_sparse_region){ambient,perms,init,0x1000ULL,16ULL};
    memory.regions=&original;memory.region_count=1;memory.space_id=433;
    memory.events=events;memory.event_capacity=8;memory.steps_left=1000;
    CHECK(aether_arena_init(&arena,&memory,0x1000ULL,512ULL));
    CHECK(aether_arena_enter(&arena,&scopes[0],16,bytes[0],permissions[0],initialized[0]));
    CHECK(scopes[0].base==0x1010ULL && scopes[0].token!=0);
    t0=scopes[0].token;
    if(mode==8) {
        CHECK(aether_arena_leave(&arena,&scopes[0],t0));arena.next_token=ULLONG_MAX;
        CHECK(!aether_arena_enter(&arena,&scopes[1],16,bytes[1],permissions[1],initialized[1]));
        CHECK(arena.depth==0 && memory.regions==&original && memory.status==1);return 0;
    }
    if(mode==9) {
        for(i=1;i<16;++i)CHECK(aether_arena_enter(&arena,&scopes[i],16,bytes[i],permissions[i],initialized[i]));
        CHECK(!aether_arena_enter(&arena,&scopes[16],16,bytes[16],permissions[16],initialized[16]));
        CHECK(arena.depth==16);
        for(i=16;i>0;--i)CHECK(aether_arena_leave(&arena,&scopes[i-1],scopes[i-1].token));
        CHECK(memory.regions==&original && arena.depth==0 && memory.status==1);return 0;
    }
    if(mode<=2) {
        CHECK(aether_arena_enter(&arena,&scopes[1],16,bytes[1],permissions[1],initialized[1]));
        t1=scopes[1].token;CHECK(t1>t0 && scopes[1].base==0x1020ULL);
        if(mode==1)CHECK(!aether_arena_leave(&arena,&scopes[1],t0));
        if(mode==2)CHECK(!aether_arena_leave(&arena,&scopes[0],t0));
        CHECK(arena.depth==2 && memory.regions==scopes[1].frame.table);
        CHECK(aether_arena_leave(&arena,&scopes[1],t1));
        CHECK(memory.regions==scopes[0].frame.table);
        CHECK(!aether_arena_leave(&arena,&scopes[1],t1));
        CHECK(aether_arena_leave(&arena,&scopes[0],t0));
        CHECK(memory.regions==&original && memory.region_count==1 && arena.depth==0);return 0;
    }
    if(mode==3)memory.regions[0].base+=16;
    if(mode==4)memory.regions=0;
    if(mode==5)original.length=8;
    if(mode==6)memory.events=0;
    if(mode==7)arena.base+=16;
    CHECK(!aether_arena_leave(&arena,&scopes[0],t0));
    CHECK(memory.status==1 && memory.regions==&original && memory.region_count==1);
    CHECK(memory.events==events && memory.event_capacity==8);
    CHECK(arena.base==0x1000ULL && arena.depth==0 && !arena.top && !scopes[0].frame.active);
    return 0;
}

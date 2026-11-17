__declspec(dllexport) unsigned int arena_extra_scenario(unsigned int mode) {
    struct aether_sparse_memory memory;
    struct aether_sparse_region original;
    struct aether_arena_context arena;
    struct aether_arena_scope first,second;
    unsigned char ambient[16],perms[16],init[16],bytes[16],permissions[16],initialized[16];
    unsigned char child[16],child_permissions[16],child_initialized[16];
    unsigned long long i,old_token,new_token;
    arena_zero(&memory,sizeof(memory));arena_zero(&arena,sizeof(arena));
    arena_zero(&first,sizeof(first));arena_zero(&second,sizeof(second));
    arena_zero(ambient,sizeof(ambient));arena_zero(init,sizeof(init));
    arena_zero(bytes,sizeof(bytes));arena_zero(initialized,sizeof(initialized));
    arena_zero(child,sizeof(child));arena_zero(child_initialized,sizeof(child_initialized));
    for(i=0;i<16;++i)perms[i]=permissions[i]=child_permissions[i]=3;
    original=(struct aether_sparse_region){ambient,perms,init,0x1000ULL,16ULL};
    memory.regions=&original;memory.region_count=1;memory.space_id=433;memory.steps_left=1000;
    CHECK(aether_arena_init(&arena,&memory,0x1000ULL,512ULL));
    CHECK(aether_arena_enter(&arena,&first,16,bytes,permissions,initialized));
    old_token=first.token;
    if(mode==0) {
        CHECK(aether_arena_leave(&arena,&first,old_token));
        CHECK(memory.status==0 && arena.depth==0 && !arena.top && memory.regions==&original);
        CHECK(aether_arena_enter(&arena,&first,16,bytes,permissions,initialized));
        new_token=first.token;CHECK(new_token>old_token && first.base==0x1010ULL);
        CHECK(!aether_arena_leave(&arena,&first,old_token));
        CHECK(arena.depth==1 && arena.top==&first && first.frame.active && first.token==new_token);
        CHECK(aether_arena_leave(&arena,&first,new_token));
        CHECK(memory.status==1);
    } else if(mode==1) {
        memory.status=7U;
        CHECK(aether_arena_leave(&arena,&first,old_token));
        CHECK(memory.status==7U);
    } else {
        memory.regions[0].length=8ULL;
        CHECK(!aether_arena_enter(&arena,&second,16,child,child_permissions,child_initialized));
        CHECK(arena.depth==1 && arena.top==&first && !second.frame.active && !second.arena);
        CHECK(!aether_arena_leave(&arena,&first,old_token));
        CHECK(memory.status==1U);
    }
    CHECK(memory.regions==&original && memory.region_count==1 && arena.depth==0 && !arena.top);
    CHECK(!first.frame.active && !first.arena);
    return 0;
}

__declspec(dllexport) unsigned int wrapped_scenario(unsigned int mode) {
    struct aether_sparse_memory memory;
    struct aether_sparse_event events[32];
    struct aether_sparse_region original;
    struct aether_arena_context arena;
    unsigned char bytes[16],permissions[16],initialized[16];
    unsigned long long i,value,base=0x1000ULL,span=512ULL;
    unsigned int expected=0;
    arena_zero(&memory,sizeof(memory));arena_zero(&arena,sizeof(arena));
    for(i=0;i<16;++i){bytes[i]=0xA5U;permissions[i]=3;initialized[i]=1;}
    original=(struct aether_sparse_region){bytes,permissions,initialized,0x1000ULL,16ULL};
    memory.regions=&original;memory.region_count=1;memory.space_id=433;
    memory.events=events;memory.event_capacity=32;memory.steps_left=1000;
    if(mode==1){memory.steps_left=0;expected=2;}
    if(mode==2){span=16;expected=1;}
    if(mode==3){base=ULLONG_MAX-15ULL;span=16;memory.regions=0;memory.region_count=0;expected=1;}
    if(mode==4){memory.space_id=434;expected=3;}
    if(mode==5){memory.event_capacity=0;expected=7;}
    CHECK(aether_arena_init(&arena,&memory,base,span));
    value=aether_model_arena_entry(&arena,1ULL,2ULL);
    CHECK(memory.status==expected);
    CHECK(value==(expected?0ULL:3ULL));
    CHECK(arena.depth==0 && !arena.top);
    CHECK(memory.regions==(mode==3?0:&original) && memory.region_count==(mode==3?0ULL:1ULL));
    CHECK(arena.next_token==(mode==2?1ULL:2ULL));
    for(i=0;i<16;++i)CHECK(bytes[i]==0xA5U);
    if(!expected){CHECK(memory.event_count==4 && events[0].address==0x1010ULL);}
    if(mode==6){
        memory.event_count=0;memory.steps_left=1000;memory.steps_executed=0;
        CHECK(aether_model_arena_entry(&arena,1ULL,2ULL)==3ULL);
        CHECK(!memory.status && arena.next_token==3ULL && arena.depth==0 && memory.regions==&original);
    }
    return 0;
}


struct modules_array
{
    mods: *mut *mut module,
    mods_cnt: i32,
    mods_cap: i32
}

fn add_module(arr: *mut modules_array, mod: *mut module) -> i32
{
    let mods: *mut *mut module;
    if (*arr).mods_cnt == (*arr).mods_cap
    {
        (*arr).mods_cap = max(16, (*arr).mods_cap * 3 / 2);
        mods = krealloc_array((*arr).mods, (*arr).mods_cap, mem::size_of::<*mut module>(), GFP_KERNEL);
        if mods.is_null()
        {
            return -ENOMEM;
        }
        (*arr).mods = mods;
    }
    (*arr).mods[(*arr).mods_cnt as usize] = mod;
    (*arr).mods_cnt += 1;
    return 0;
}

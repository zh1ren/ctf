// from ghidra decompilation

global vars: winner_idx, ctfs_arr;

undefined8 main(void){
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 0;
  init();
  intro();
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          menu();
          __isoc99_scanf("%d",&local_14);
          if (local_14 != 1) break;
          add_ctf();
        }
        if (local_14 != 2) break;
        vote_ctf();
      }
      if (local_14 != 3) break;
      remove_ctf();
    }
  } while (local_14 != 4);
  bin_exit();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
// add_ctf funcs
// ---------------------------------------------------------------------------

void add_ctf(void){
  short width;
  short height;
  short j;
  short k;
  int idx;
  int topics_n;
  int i;
  basic_string topic_name [32];
  basic_string local_48 [40];
  ...

  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (9 < ctfs_n) {
    puts("already full");
    exit(-1);
  }
  printf("idx? ");
  __isoc99_scanf("%d",&idx);
  if ((idx < 0) || (9 < idx)) {
    exit(-1);
  }
  if (*(long *)(&ctfs_arr + (long)idx * 8) != 0) {
    exit(-1);
  }

  pvVar3 = operator.new(0x958);
  setup_obj(pvVar3,idx);
  *(void **)(&ctfs_arr + (long)idx * 8) = pvVar3;
  printf("name? ");
  uVar4 = obj->name(*(undefined8 *)(&ctfs_arr + (long)idx * 8)); 
  // long obj->name(long param_1) {  return param_1 + 0x18; }
  __isoc99_scanf(" %31s",uVar4);

  printf("topic cnt? ");
  __isoc99_scanf("%d",&topics_n);
  if (5 < topics_n) {
    exit(-1);
  }
  i = 0;
  while (i < topics_n) {
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string();
    std::operator<<((basic_ostream *)std::cout,"topic> ");
    std::operator>>((basic_istream *)std::cin,topic_name);
    cVar1 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::empty();
    if (cVar1 != '\0') {
      exit(-1);
    }
    uVar4 = *(undefined8 *)(&ctfs_arr + (long)idx * 8);
    do_nothing(topic_name);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
              (local_48);
    dk(uVar4,local_48); // I didn't reverse this func
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
              ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_48);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
              ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)topic_name);
    i = i + 1;
  }
  
  printf("wanna upload photo? ");
  __isoc99_scanf("%c",&local_7d);
  if ((local_7d == 'y') || (local_7d == 'Y')) {
    *(undefined *)(*(long *)(&ctfs_arr + (long)idx * 8) + 0xc) = 1;
    printf("width? ");
    __isoc99_scanf("%hd",&width);
    printf("height? ");
    __isoc99_scanf("%hd",&height);
    getchar();
    if ((0x2f < width) || (0x2f < height)) {
      exit(-1);
    }
    set_obj_width(*(undefined8 *)(&ctfs_arr + (long)idx * 8),(int)width,(int)width);
    set_obj_height(*(undefined8 *)(&ctfs_arr + (long)idx * 8),(int)height,(int)height);
    // void set_obj_width(long param_1,undefined2 param_2)  { *(undefined2 *)(param_1 + 0x14) = param_2; }
    // void set_obj_height(long param_1,undefined2 param_2) { *(undefined2 *)(param_1 + 0x16) = param_2; }

    puts("reading photo below>>");
    pvVar3 = (void *)obj->photo(*(undefined8 *)(&ctfs_arr + (long)idx * 8));
    // long obj->photo(long param_1) { return param_1 + 0x38; } 
    memset(pvVar3,0,8);
    pvVar3 = (void *)obj->photo(*(undefined8 *)(&ctfs_arr + (long)idx * 8));
    read(0,pvVar3,(long)((int)height * (int)width));
    set_check(*(undefined8 *)(&ctfs_arr + (long)idx * 8));
    uVar4 = obj->photo(*(undefined8 *)(&ctfs_arr + (long)idx * 8));
    printf("photo format : %s\n",uVar4);
    puts("photo rendering result below>>");
    j = 0;
    while( true ) {
      sVar2 = obj->height(*(undefined8 *)(&ctfs_arr + (long)idx * 8));
      // undefined2 obj->height(long param_1) { return *(undefined2 *)(param_1 + 0x16); }

      if (sVar2 <= j) break;
      k = 0;
      while( true ) {
        sVar2 = obj->width(*(undefined8 *)(&ctfs_arr + (long)idx * 8));
        // undefined2 obj->width(long param_1) { return *(undefined2 *)(param_1 + 0x14); }
        
        if (sVar2 <= k) break;
        lVar5 = obj->photo(*(undefined8 *)(&ctfs_arr + (long)idx * 8));
        iVar6 = (int)j;
        sVar2 = obj->width(*(undefined8 *)(&ctfs_arr + (long)idx * 8));
        if (*(char *)(((int)k + iVar6 * sVar2) + lVar5) == '1') {
          putchar(0x2b);
        }
        else {
          putchar(0x2e);
        }
        k = k + 1;
      }
      putchar(10);
      j = j + 1;
    }
    puts("\n");
  }
  else {
    *(undefined *)(*(long *)(&ctfs_arr + (long)idx * 8) + 0xc) = 0;
  }
  ctfs_n = ctfs_n + 1;
  puts("saved!");
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}

void setup_obj(undefined **param_1,undefined4 param_2){
  *param_1 = (undefined *)&PTR_FUN_00107c80; // 00107c80: FUN_00104522
  *(undefined4 *)(param_1 + 1) = 0;
  *(undefined *)((long)param_1 + 0xc) = 0;
  FUN_00103406(param_1 + 0x128); // doesn't do much except setting some 0s
  *(undefined4 *)(param_1 + 2) = param_2;
  return;
}

void set_check(long obj){
  long lVar1;

  lVar1 = generate_magic(obj);
  /* if magic not 0x1337133713371337, then set the magic */
  if (lVar1 != 0x1337133713371337) {
    *(long *)(obj + 0x938) = lVar1;
  }
  return;
}

long generate_magic(long obj){
  short j;
  long local_10;

  local_10 = 0x1337133713371337;
  j = 0;
  while (((((int)j < (int)*(short *)(obj + 0x16) * (int)*(short *)(obj + 0x14) &&
           (-1 < *(short *)(obj + 0x14))) && (-1 < *(short *)(obj + 0x16))) && (j < 0x900))) {
    local_10 = (long)*(char *)(obj + 0x38 + (long)(int)j) + local_10 * 0x17;
    j = j + 1;
  }
  return local_10;
}

// vote_ctf funcs
// ---------------------------------------------------------------------------

void vote_ctf(void){
  ...

  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (ctfs_n < 1) {
    puts("not found");
  }
  else {
    putchar(10);
    puts("< ctf list >");
    i = 0;
    while ((int)i < 10) {
      if (*(long *)(&ctfs_arr + (long)(int)i * 8) != 0) {
        puts("----------------------------------------");
        uVar3 = obj->name(*(undefined8 *)(&ctfs_arr + (long)(int)i * 8));
        printf("<%d> [%s]\n",(ulong)i,uVar3);
        if (*(char *)(*(long *)(&ctfs_arr + (long)(int)i * 8) + 0xc) != '\0') {
          cVar1 = negative_check(*(undefined8 *)(&ctfs_arr + (long)(int)i * 8));
          if (cVar1 != '\x01') {
            puts("I know what you r doing");
            exit(-1);
          }
          uVar3 = obj->name(*(undefined8 *)(&ctfs_arr + (long)(int)i * 8));
          printf("(%s logo)\n",uVar3);
                    /* print photo
                        */
          j = 0;
          while( true ) {
            sVar2 = obj->height(*(undefined8 *)(&ctfs_arr + (long)(int)i * 8));
            if (sVar2 <= j) break;
            local_2a = 0;
            while( true ) {
              sVar2 = obj->width(*(undefined8 *)(&ctfs_arr + (long)(int)i * 8));
              if (sVar2 <= local_2a) break;
              lVar4 = obj->photo(*(undefined8 *)(&ctfs_arr + (long)(int)i * 8));
              sVar2 = obj->width(*(undefined8 *)(&ctfs_arr + (long)(int)i * 8));
              if (*(char *)(((int)local_2a + (int)j * (int)sVar2) + lVar4) == '1') {
                putchar(0x2b);
              }
              else {
                putchar(0x2e);
              }
              local_2a = local_2a + 1;
            }
            putchar(10);
            j = j + 1;
          }
          putchar(10);
        }
        print_logo(*(undefined8 *)(&ctfs_arr + (long)(int)i * 8)); // didn't reverse this func, just guessed it
      }
      i = i + 1;
    }
    puts("----------------------------------------\n");
    printf("vote to your favorite ctf idx: ");
    __isoc99_scanf("%d",&local_28);
    if (*(long *)(&ctfs_arr + (long)local_28 * 8) == 0) {
      puts("?");
      exit(-1);
    }
    *(int *)(*(long *)(&ctfs_arr + (long)local_28 * 8) + 8) =
         *(int *)(*(long *)(&ctfs_arr + (long)local_28 * 8) + 8) + 1;
    if (winner_idx == -1) {
      winner_idx = local_28;
    }
    else {
      if (*(int *)(*(long *)(&ctfs_arr + (long)winner_idx * 8) + 8) <
          *(int *)(*(long *)(&ctfs_arr + (long)local_28 * 8) + 8)) {
        puts("Winner Changed!!!!!");
        winner_idx = local_28;
      }
    }
    puts("thank you!\n");
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}

ulong negative_check(long param_1){
  ulong uVar1;
  ulong uVar2;

  uVar1 = *(ulong *)(param_1 + 0x938);
  uVar2 = generate_magic(param_1);
  return uVar2 & 0xffffffffffffff00 | (ulong)(uVar1 == uVar2);
}

// remove_ctf func
// ---------------------------------------------------------------------------

void remove_ctf(void){
  ...

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (ctfs_n < 1) {
    puts("already empty");
    exit(-1);
  }
  printf("idx? ");
  __isoc99_scanf("%d",&local_14);
  if ((local_14 < 0) || (9 < local_14)) {
    exit(-1);
  }
  if (*(long *)(&ctfs_arr + (long)local_14 * 8) == 0) {
    puts("empty idx");
    exit(-1);
  }
  if (*(char *)(*(long *)(&ctfs_arr + (long)local_14 * 8) + 0xc) != '\0') {
    cVar3 = negative_check(*(undefined8 *)(&ctfs_arr + (long)local_14 * 8));
    if (cVar3 != '\x01') {
      bVar2 = true;
      goto LAB_00103118;
    }
  }
  bVar2 = false;
LAB_00103118:
  if (bVar2) {
    puts("I know what you r doing");
    exit(-1);
  }
  plVar1 = *(long **)(&ctfs_arr + (long)local_14 * 8);
  if (plVar1 != (long *)0x0) {
    (**(code **)(*plVar1 + 8))(plVar1);
  }
  *(undefined8 *)(&ctfs_arr + (long)local_14 * 8) = 0;
  ctfs_n = ctfs_n + -1;
  puts("deleted");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}

void init(void){
  local_14 = open("/home/acs_ctf/flag",0);
  read(local_14,&local_18,4);
  srand(local_18);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  signal(0xe,exit);
  signal(0xb,correct_indicate);
  alarm(0x78);
  return;
}

undefined8 main(void){
  ... 
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  init();
  local_134 = 0;
  local_128[0] = 0xdeadbeef;
  local_128[1] = 0xcafebabe;
  local_128[2] = 0x1337c0d3;
  local_128[3] = 0x79427942;
  ...
  do {
    puts("a drop of tear makes me relieved.");
    local_134 = get_signedint(&local_134);
    if (local_134 == 0x10001) {
      guessed_num();
    }
    else {
      if ((int)local_134 < 0x10002) {
        if (local_134 == 0x67) {
          puts("one drop of tear will be dropped.");
          exit(0);
        }
        if ((int)local_134 < 0x68) {
          if (local_134 == 0x65) {
            puts("test your luck.");
            __isoc99_scanf("%c",&local_130);
            getchar();
            if (0x44 < local_130) {
              puts("wrong choice");
              exit(-1);
            }
            local_130 = local_128[(int)((local_130 & 0xff) - 0x41)];  //<--- NEGATIVE INDEX
            puts("what if choice is.....?");
            __isoc99_scanf("%c",&local_135);
            getchar();
            if (local_135 == '/') {
              puts("divided by...?");
              __isoc99_scanf("%d",&local_12c);
              getchar();
              local_130 = (int)local_130 / local_12c;
            }
            else {
              if (local_135 < '0') {
                if (local_135 == '-') {
                  puts("minus...?");
                  __isoc99_scanf("%d",&local_12c);
                  getchar();
                  local_130 = local_130 - local_12c;
                }
                else {
                  if (local_135 < '.') {
                    if (local_135 == '*') {
                      puts("multiply...?");
                      __isoc99_scanf("%d",&local_12c);
                      getchar();
                      local_130 = local_12c * local_130;
                    }
                    else {
                      if (local_135 == '+') {
                        puts("plus...?");
                        __isoc99_scanf("%d",&local_12c);
                        getchar();
                        local_130 = local_12c + local_130;
                      }
                    }
                  }
                }
              }
            }
            uVar1 = rand();
            if (uVar1 == local_130) {
              puts("Correct! wow..");
              guessed_num();
            }
            else {
              puts("..?");
            }
            goto LAB_00101a39;
          }
          if (local_134 == 0x66) {
            puts("test your exploit skill.");
            read(0,&local_118,0x140); // <----- BUFFER OVERFLOW HERE
            if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
              return 0;
            }
            __stack_chk_fail();
          }
        }
      }
      printf("%d is wrong choice.\n",(ulong)local_134);
    }
LAB_00101a39:
    puts("");
  } while( true );
}

void get_signedint(char *param_1){
  read(0,param_1,4);
  atoi(param_1);
  return;
}

void guessed_num(void){
  long in_FS_OFFSET;
  uint local_20;
  uint local_1c;
  int local_18;
  int local_14;
  long local_10;

  local_18 = open("/home/acs_ctf/flag",0);
  read(local_18,&local_20,4);
  close(local_18);
  __isoc99_scanf("%d",&local_1c);
  if (local_20 != local_1c) {
    puts("Wrong!");
    exit(-1);
  }
  puts("Correct");
  local_14 = open("/home/acs_ctf/flag",0);
  read(local_14,&local_1c,4);
  local_1c = local_1c & 0xffffff;
  printf("Of course, you are playing %s CTF, right?\n",&local_1c);
  close(local_14);
  return;
}

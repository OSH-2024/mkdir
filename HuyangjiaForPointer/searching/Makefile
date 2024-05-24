SRC1 = c_sourse/c_pointer.c
SRC2 = src/lib.rs
SRC3 = c_sourse/main.c

make:
	gcc -shared -o libc_pointer.so $(SRC1)
	rustc $(SRC2) --crate-type cdylib -C prefer-dynamic -l dylib=c_pointer -L .
	gcc -g c_sourse/main.c -L. -L/home/ubuntu/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib -lc_pointer -llib -Wl,-rpath,. -Wl,-rpath,/home/ubuntu/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib -o main

# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/ubuntu/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib
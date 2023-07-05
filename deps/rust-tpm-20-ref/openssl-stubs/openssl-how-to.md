
## Run ```process_openssl.pl```

when update opensslversion

mkdir -p conf-include/openssl;
mkdir -p conf-include/crypto;
CC=clang AR=llvm-ar CFLAGS="-Wall -Werror -Wno-format -target x86_64-unknown-none -fPIC -nostdlib -nostdlibinc -ffreestanding -Istd-include -Iconf-include -Iarch/x86_64 -include CrtLibSupport.h -std=c99" ./process_openssl.pl

make -j$(nproc) libcrypto.a
cp libcrypto.a crypto.lib

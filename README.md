# Kui

Kui(夔) is a loadable module which designed for verifying ELF.

### Build from Source
---

Kui need openssl library to compile sub module.

```shell
git clone https://github.com/Explainaur/Kui.git
cd Kui
make -j8
```

### Usage
---

Kui can hook syscall `execve()` to check ELF file. If the ELF is not signed or verified failed. It won't execute. You can use [ELFSign](https://github.com/Explainaur/ELFSign) to sign ELF and verify it.

```
insmod kui.ko      # Install Kui module
modinfo kui        # Check if module install
rmmod kui          # Remove Kui module
```

You need to place the public key into `/etc/kui/pubkey` and place the certificate into `/etc/kui/X509`. You can use ELFSign to generate key pair and certificate.

In order to better show the demo's operation, I limited the work dir. You need to change `LIMITED_DIR` in `Kui/include/config.h` to you test directory. Then all ELF file in `LIMITED_DIR` will be hooked!

### License
---

Copyright (C) 2016-2020 dyf. License GPLv2.

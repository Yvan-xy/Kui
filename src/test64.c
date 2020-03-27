#include "../include/elf_64.h"

void Elf64BaseTester(void) {
	int ret;
	Elf64 elf64;
	bool isElf;
	pr_info("---------- ELF64 Base Function TEST ----------");
	isElf = IsELF64("/home/code/solo/rubbish/hardwork/casual/unix/kernel/a");
	if (!isElf) {
		pr_err("File is not ELF64, ret is %d\n", isElf);
		return;
	}
	else {
		pr_info("Is ELF check pass!");
	}

	SetElf64Path(&elf64, "/home/code/solo/rubbish/hardwork/casual/unix/kernel/a\0");
	pr_info("ELF path is %s", elf64.path);
	ret = strcmp(elf64.path, "/home/code/solo/rubbish/hardwork/casual/unix/kernel/a\0");
	if (ret != 0) {
		pr_err("Set ELF path failed, ret is %d", ret);
		return;
	} else {
		pr_info("Set ELF path check pass!");
	}

    // Test reading Section Header offset
    ret = GetEhdr64(&elf64);
	if (!ret) {
		pr_err("Read ELF Header failed");
		return;
	} else {
		pr_info("Read ELF Header success!");
	}
	pr_info("----------> ELF Header");
	pr_info("Section Header Offset is %ld(0x%x)", elf64.ehdr.e_shoff, elf64.ehdr.e_shoff);
	pr_info("Size of Section Header Entry %d(0x%x)", elf64.ehdr.e_shentsize, elf64.ehdr.e_shentsize);
    pr_info("Section header string table index %d(0x%x)", elf64.ehdr.e_shstrndx, elf64.ehdr.e_shstrndx);

    // Test reading Section name string table section header
	ret = Getshstrtabhdr64(&elf64);
    if (!ret) {
		pr_err("Read shstrtab Header failed");
		return;
	} else {
		pr_info("Read shstrtab Header success!");
	}
    pr_info("shstrtab offset is %d(0x%x)", elf64.shstrtabhdr.sh_offset, elf64.shstrtabhdr.sh_offset);
    pr_info("shstrtab size is %d(0x%x)", elf64.shstrtabhdr.sh_size, elf64.shstrtabhdr.sh_size);
    pr_info("Section shstrtab aligned size %d(0x%x)", elf64.shstrtabhdr.sh_addralign, elf64.shstrtabhdr.sh_addralign);
    pr_info("Name offset in shstrtab %d(0x%x)", elf64.shstrtabhdr.sh_name, elf64.shstrtabhdr.sh_name);

    // Test reading shstrtab contain
    ret = Getshstrtab64(&elf64);
	if (!ret) {
		pr_err("Read shstrtab failed");
		return;
	} else {
		pr_info("Read shstrtab success");
	}

//    for (uint16_t i = 0; i < elf64.shstrtabhdr.sh_size; i++) {
//        if (elf64.shstrtab[i] == 0)
//            pr_info(" ");
//        else
//            pr_info("%c", elf64.shstrtab[i]);
//    }

    // Test get elf file size
    pr_info("\n----------> Rewrite ELF");
    long int size = GetFileSize64(&elf64);
    if (size != elf64.size) {
		pr_err("Read file size failed");
		return;
	} else {
		pr_info("Read file size success");
	}
    pr_info("ELF file size is %ld(0x%x)", elf64.size, elf64.size);

	
	// Hash .text 
	HashText64(&elf64);
	for (int i = 0; i < 20; i++)
    	pr_info("0x%x ", elf64.digest[i]);


	Destract64(&elf64);
	pr_info("ELF64 base function test pass!\n");
}
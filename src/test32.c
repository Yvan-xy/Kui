#include "../include/elf_32.h"

void Elf32BaseTester(void) {
	int ret;
	Elf32 elf32;
	bool isElf;
	pr_info("---------- ELF32 Base Function TEST ----------");
	isElf = IsELF32("/home/code/solo/rubbish/hardwork/casual/unix/kernel/a");
	if (!isElf) {
		pr_err("File is not ELF32, ret is %d", isElf);
		return;
	}
	else {
		pr_info("Is ELF check pass!");
	}

	SetElf32Path(&elf32, "/home/code/solo/rubbish/hardwork/casual/unix/kernel/a\0");
	pr_info("ELF path is %s", elf32.path);
	ret = strcmp(elf32.path, "/home/code/solo/rubbish/hardwork/casual/unix/kernel/a\0");
	if (ret != 0) {
		pr_err("Set ELF path failed, ret is %d", ret);
		return;
	} else {
		pr_info("Set ELF path check pass!");
	}

    // Test reading Section Header offset
    ret = GetEhdr32(&elf32);
	if (!ret) {
		pr_err("Read ELF Header failed");
		return;
	} else {
		pr_info("Read ELF Header success!");
	}
	pr_info("----------> ELF Header");
	pr_info("Section Header Offset is %ld(0x%x)", elf32.ehdr.e_shoff, elf32.ehdr.e_shoff);
	pr_info("Size of Section Header Entry %d(0x%x)", elf32.ehdr.e_shentsize, elf32.ehdr.e_shentsize);
    pr_info("Section header string table index %d(0x%x)", elf32.ehdr.e_shstrndx, elf32.ehdr.e_shstrndx);

    // Test reading Section name string table section header
	ret = Getshstrtabhdr32(&elf32);
    if (!ret) {
		pr_err("Read shstrtab Header failed");
		return;
	} else {
		pr_info("Read shstrtab Header success!");
	}
    pr_info("shstrtab offset is %d(0x%x)", elf32.shstrtabhdr.sh_offset, elf32.shstrtabhdr.sh_offset);
    pr_info("shstrtab size is %d(0x%x)", elf32.shstrtabhdr.sh_size, elf32.shstrtabhdr.sh_size);
    pr_info("Section shstrtab aligned size %d(0x%x)", elf32.shstrtabhdr.sh_addralign, elf32.shstrtabhdr.sh_addralign);
    pr_info("Name offset in shstrtab %d(0x%x)", elf32.shstrtabhdr.sh_name, elf32.shstrtabhdr.sh_name);

    // Test reading shstrtab contain
    ret = Getshstrtab32(&elf32);
	if (!ret) {
		pr_err("Read shstrtab failed");
		return;
	} else {
		pr_info("Read shstrtab success");
	}

//    for (uint16_t i = 0; i < elf32.shstrtabhdr.sh_size; i++) {
//        if (elf32.shstrtab[i] == 0)
//            pr_info(" ");
//        else
//            pr_info("%c", elf32.shstrtab[i]);
//    }

    // Test get elf file size
    pr_info("\n----------> Rewrite ELF");
    long int size = GetFileSize32(&elf32);
    if (size != elf32.size) {
		pr_err("Read file size failed");
		return;
	} else {
		pr_info("Read file size success");
	}
    pr_info("ELF file size is %ld(0x%x)", elf32.size, elf32.size);

	
	// Hash .text 
	HashText32(&elf32);
	for (int i = 0; i < 20; i++)
    	pr_info("0x%x ", elf32.digest[i]);

	Destract32(&elf32);
	pr_info("ELF32 base function test pass!\n");
}
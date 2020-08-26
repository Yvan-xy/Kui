#! /bin/bash
user=$(whoami)
if [[ $user != "root" ]]
then
    echo "Please use root run this shell!"
    exit 127
fi
make -j8

mkdir /etc/Kui
mkdir /etc/Kui/X509
mkdir /etc/Kui/pubkey

insmod kui.ko
echo "Install Kui success!"

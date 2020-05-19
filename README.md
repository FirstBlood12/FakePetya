# FakePetya

A source code of the FakePetya

# Disclaimer:

This is a MBR/GPT infecting virus, (don't compile and run if you don't know the risks!)

Don't run this virus on your host, use Virtual Machine

It rewrites MBR/GPT with petya bootloader, the bootloader passes control to the kernel and displays petya ransomware message
however if u enter any 16 byte key, the mbr will be restored

# Prerequisites:

Microsoft Visual Studio 2010 and later Only use Win32/Release configuration because Debug is not configured properly

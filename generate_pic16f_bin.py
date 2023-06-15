with open("test_firmware.bin", "wb+") as fout:
    fout.write(int(0b0011111101111000).to_bytes(2, 'little') + int(0b0011111101111010).to_bytes(2, 'little'))
    fout.close()
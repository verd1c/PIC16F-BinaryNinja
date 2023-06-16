with open("test_firmware.bin", "wb+") as fout:
    fout.write(int(0b0000101011111111).to_bytes(2, 'big') + int(0b0011100011111111).to_bytes(2, 'big'))
    fout.close()
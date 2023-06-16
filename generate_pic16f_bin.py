with open("test_firmware.bin", "wb+") as fout:
    fout.write(int(0b0000011111111111).to_bytes(2, 'big') + int(0b0001010000000000).to_bytes(2, 'big') + int(0b0000011111101110).to_bytes(2, 'big') + int(0b0000011111011101).to_bytes(2, 'big') + int(0b0000011111100101).to_bytes(2, 'big'))
    fout.close()
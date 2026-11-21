# SM4 (SMS4) S-box, copied from the public IETF draft "The SM4 Blockcipher Algorithm"
# (draft-ribose-cfrg-sm4-10, Tse, Wong, Saarinen, 2018), section 6.2.3, Figure 1,
# https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10 (same table as GB/T 32907-2016).
# Not taken from sneak_n2.py. Check: S(0xEF) = 0x84 (the draft's worked example).
SM4_SBOX = bytes.fromhex("d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa441326498606999c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa64707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d351e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89eeabf8ad240c738b5a3f7f2cef96115a1e0ae5da49b341a55ad933230f58cb1e31df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b518d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b08969974a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3ed7cb3948")
assert len(set(SM4_SBOX)) == 256 and SM4_SBOX[0xEF] == 0x84

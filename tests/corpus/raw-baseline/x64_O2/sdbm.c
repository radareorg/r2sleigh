uint64_t sym__sdbm(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 127 source obligations: 97 rendered, 30 elided, 0 refused; 37 statements rendered */
    if (RSI_0 == 0) {
        return 0;
    } else {
        uint64_t RDX_1;
        uint64_t RAX_1;
        uint64_t RCX_2 = (uint64_t)(uint32_t)((uint32_t)RSI_0 & 3);
        if (4 <= RSI_0) {
            uint64_t RDX_2;
            uint64_t RAX_2;
            RSI_0 &= (uint64_t)-0x4;
            RDX_2 = (uint64_t)0;
            RAX_2 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RDX_2];
                uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RDX_2 + 1];
                uint8_t tmp_11e00_4 = ((uint8_t*)RDI_0)[RDX_2 + 2];
                uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RDX_2 + 3];
                RAX_2 = (uint64_t)(uint32_t)((uint32_t)tmp_11e00_5 + (uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_4 + (uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_3 + (uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_2 + (uint32_t)((uint64_t)(int32_t)RAX_2 * 0x1003f)) * 0x1003f)) * 0x1003f)) * 0x1003f));
                RDX_2 += 4;
                uint8_t tmp_12800_2 = RSI_0 != RDX_2;
                RAX_1 = RAX_2;
                RDX_1 = RDX_2;
                if (!tmp_12800_2) {
                    break;
                }
            }
        } else {
            RDX_1 = (uint64_t)0;
            RAX_1 = (uint64_t)0;
        }
        {
            if (RCX_2 != 0) {
                uint64_t RDX_6;
                RDI_0 += RDX_1;
                RDX_6 = (uint64_t)0;
                for (; ; ) {
                    uint8_t tmp_11e00_8 = ((uint8_t*)RDI_0)[RDX_6];
                    RAX_1 = (uint64_t)(uint32_t)((uint32_t)tmp_11e00_8 + (uint32_t)((uint64_t)(int32_t)RAX_1 * 0x1003f));
                    RDX_6++;
                    uint8_t tmp_12800_5 = RCX_2 != RDX_6;
                    if (!tmp_12800_5) {
                        break;
                    }
                }
            }
            return RAX_1;
        }
    }
}


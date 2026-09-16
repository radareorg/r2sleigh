uint64_t sym__unaligned_words(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 80 source obligations: 56 rendered, 24 elided, 0 refused; 27 statements rendered */
    {
        uint64_t RAX_1;
        uint64_t RCX_1;
        RAX_1 = 0x9e3779b9;
        if (8 <= RSI_0) {
            uint64_t RDX_1;
            RDX_1 = (uint64_t)0;
            for (; ; ) {
                uint32_t tmp_11f00_2 = *(uint32_t*)(RDI_0 + RDX_1 + 1);
                RAX_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)((uint32_t)RAX_1 ^ tmp_11f00_2) * 0x1000193);
                uint64_t RCX_3 = RDX_1 + 7;
                uint64_t tmp_3f080_2 = RDX_1 + 15;
                uint64_t RDX_4 = RCX_3;
                RDX_1 = RDX_4;
                RCX_1 = RCX_3;
                if (RSI_0 < tmp_3f080_2) {
                    break;
                }
            }
        } else {
            RCX_1 = (uint64_t)0;
        }
        {
            uint8_t tmp_12700_2 = RSI_0 <= RCX_1;
            if (!tmp_12700_2) {
                for (; ; ) {
                    uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                    RAX_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_2 ^ (uint32_t)RAX_1) * 0x1000193);
                    RCX_1++;
                    uint8_t tmp_12800_2 = RSI_0 != RCX_1;
                    if (!tmp_12800_2) {
                        break;
                    }
                }
            }
            return RAX_1;
        }
    }
}


uint64_t sym__fnv1a64(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 114 source obligations: 82 rendered, 32 elided, 0 refused; 30 statements rendered */
    {
        int64_t R8_1;
        R8_1 = (int64_t)0xcbf29ce484222325U;
        if (RSI_0 == 0) {
            return (uint64_t)R8_1;
        } else {
            uint64_t R9_1;
            uint64_t RDX_2 = (uint64_t)((uint32_t)RSI_0 & 3);
            if (4 <= RSI_0) {
                RSI_0 &= (uint64_t)-0x4;
                R9_1 = (uint64_t)0;
                for (; ; ) {
                    uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[R9_1];
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[R9_1 + 1];
                    uint8_t tmp_11e00_4 = ((uint8_t*)RDI_0)[R9_1 + 2];
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[R9_1 + 3];
                    R8_1 = (int64_t)((((((uint64_t)R8_1 ^ (uint64_t)tmp_11e00_2) * 0x100000001b3 ^ (uint64_t)tmp_11e00_3) * 0x100000001b3 ^ (uint64_t)tmp_11e00_4) * 0x100000001b3 ^ (uint64_t)tmp_11e00_5) * 0x100000001b3);
                    R9_1 += 4;
                    if (RSI_0 == R9_1) {
                        break;
                    }
                }
            } else {
                R9_1 = (uint64_t)0;
            }
            {
                if (RDX_2 != 0) {
                    uint64_t RSI_3;
                    RDI_0 += R9_1;
                    RSI_3 = (uint64_t)0;
                    for (; ; ) {
                        uint8_t tmp_11e00_8 = ((uint8_t*)RDI_0)[RSI_3];
                        R8_1 = (int64_t)(((uint64_t)R8_1 ^ (uint64_t)tmp_11e00_8) * 0x100000001b3);
                        RSI_3++;
                        if (RDX_2 == RSI_3) {
                            break;
                        }
                    }
                }
                return (uint64_t)R8_1;
            }
        }
    }
}


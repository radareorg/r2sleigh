uint64_t sym__fnv1a64(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 116 source obligations: 84 rendered, 32 elided, 0 refused; 56 statements rendered */
    {
        int64_t R8_1;
        R8_1 = (int64_t)0xcbf29ce484222325U;
        uint64_t tmp_70500_1 = RSI_0;
        if (tmp_70500_1 == 0) {
            int64_t RAX_15 = R8_1;
            return (uint64_t)RAX_15;
        } else {
            uint64_t R9_1;
            uint32_t tmp_lane_100000623_5_3_1 = (uint32_t)RSI_0 & 3;
            uint64_t RDX_2 = (uint64_t)(uint32_t)tmp_lane_100000623_5_3_1;
            uint64_t tmp_3ea80_1 = RSI_0;
            if (4 <= tmp_3ea80_1) {
                uint64_t R9_2;
                RSI_0 &= (uint64_t)-0x4;
                R9_2 = (uint64_t)0;
                for (; ; ) {
                    int64_t RAX_7;
                    int64_t RAX_3;
                    int64_t R8_4;
                    uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[R9_2];
                    RAX_3 = (int64_t)((uint64_t)R8_1 ^ (uint64_t)tmp_11e00_2);
                    RAX_3 = (int64_t)((uint64_t)RAX_3 * 0x100000001b3);
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[R9_2 + 1];
                    R8_4 = (int64_t)((uint64_t)RAX_3 ^ (uint64_t)tmp_11e00_3);
                    R8_4 = (int64_t)((uint64_t)R8_4 * 0x100000001b3);
                    uint8_t tmp_11e00_4 = ((uint8_t*)RDI_0)[R9_2 + 2];
                    RAX_7 = (int64_t)((uint64_t)R8_4 ^ (uint64_t)tmp_11e00_4);
                    RAX_7 = (int64_t)((uint64_t)RAX_7 * 0x100000001b3);
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[R9_2 + 3];
                    R8_1 = (int64_t)((uint64_t)RAX_7 ^ (uint64_t)tmp_11e00_5);
                    R8_1 = (int64_t)((uint64_t)R8_1 * 0x100000001b3);
                    R9_2 += 4;
                    uint64_t tmp_3f080_2 = RSI_0;
                    uint8_t tmp_12800_2 = tmp_3f080_2 != R9_2;
                    R9_1 = R9_2;
                    if (!tmp_12800_2) {
                        break;
                    }
                }
            } else {
                R9_1 = (uint64_t)0;
            }
            {
                int64_t RAX_14;
                int64_t RAX_9 = R8_1;
                uint64_t tmp_70500_2 = RDX_2;
                RAX_14 = RAX_9;
                if (tmp_70500_2 != 0) {
                    uint64_t RSI_3;
                    RDI_0 += R9_1;
                    RSI_3 = (uint64_t)0;
                    for (; ; ) {
                        uint8_t tmp_11e00_8 = *(uint8_t*)(RSI_3 + RDI_0);
                        R8_1 = (int64_t)((uint64_t)R8_1 ^ (uint64_t)tmp_11e00_8);
                        R8_1 = (int64_t)((uint64_t)R8_1 * 0x100000001b3);
                        RSI_3++;
                        uint64_t tmp_3f080_5 = RDX_2;
                        uint8_t tmp_12800_5 = tmp_3f080_5 != RSI_3;
                        RAX_14 = R8_1;
                        if (!tmp_12800_5) {
                            break;
                        }
                    }
                }
                return (uint64_t)RAX_14;
            }
        }
    }
}


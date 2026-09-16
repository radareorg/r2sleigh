uint64_t sym__sdbm(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 127 source obligations: 97 rendered, 30 elided, 0 refused; 60 statements rendered */
    {
        uint64_t tmp_70500_1 = RSI_0;
        if (tmp_70500_1 == 0) {
            return 0;
        } else {
            uint64_t RDX_1;
            uint64_t RAX_1;
            uint32_t tmp_lane_100000779_4_3_1 = (uint32_t)RSI_0 & 3;
            uint64_t RCX_2 = (uint64_t)(uint32_t)tmp_lane_100000779_4_3_1;
            uint64_t tmp_3ea80_1 = RSI_0;
            if (4 <= tmp_3ea80_1) {
                uint64_t RDX_2;
                uint64_t RAX_2;
                RSI_0 &= (uint64_t)-0x4;
                RDX_2 = (uint64_t)0;
                RAX_2 = (uint64_t)0;
                for (; ; ) {
                    uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RDX_2];
                    uint64_t tmp_4c780_2 = (uint64_t)(int32_t)RAX_2 * 0x1003f;
                    int32_t tmp_lane_1000007a0_8_13_1 = (int32_t)tmp_4c780_2;
                    int32_t tmp_lane_1000007a0_10_16_1 = (int32_t)((uint32_t)tmp_11e00_2 + (uint32_t)tmp_lane_1000007a0_8_13_1);
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RDX_2 + 1];
                    uint64_t tmp_4c780_3 = (uint64_t)tmp_lane_1000007a0_10_16_1 * 0x1003f;
                    int32_t tmp_lane_1000007a0_21_1a_1 = (int32_t)tmp_4c780_3;
                    int32_t tmp_lane_1000007a0_29_1d_1 = (int32_t)((uint32_t)tmp_11e00_3 + (uint32_t)tmp_lane_1000007a0_21_1a_1);
                    uint8_t tmp_11e00_4 = ((uint8_t*)RDI_0)[RDX_2 + 2];
                    uint64_t tmp_4c780_4 = (uint64_t)tmp_lane_1000007a0_29_1d_1 * 0x1003f;
                    int32_t tmp_lane_1000007a0_3a_21_1 = (int32_t)tmp_4c780_4;
                    int32_t tmp_lane_1000007a0_42_24_1 = (int32_t)((uint32_t)tmp_11e00_4 + (uint32_t)tmp_lane_1000007a0_3a_21_1);
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RDX_2 + 3];
                    uint32_t tmp_lane_1000007a0_4e_26_1 = (uint32_t)tmp_11e00_5;
                    uint64_t tmp_4c780_5 = (uint64_t)tmp_lane_1000007a0_42_24_1 * 0x1003f;
                    int32_t tmp_lane_1000007a0_53_28_1 = (int32_t)tmp_4c780_5;
                    uint32_t tmp_lane_1000007a0_5b_2b_1 = (uint32_t)tmp_lane_1000007a0_53_28_1 + tmp_lane_1000007a0_4e_26_1;
                    RAX_2 = (uint64_t)(uint32_t)tmp_lane_1000007a0_5b_2b_1;
                    RDX_2 += 4;
                    uint64_t tmp_3f080_2 = RSI_0;
                    uint8_t tmp_12800_2 = tmp_3f080_2 != RDX_2;
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
                uint64_t tmp_70500_2 = RCX_2;
                if (tmp_70500_2 != 0) {
                    uint64_t RDX_6;
                    RDI_0 += RDX_1;
                    RDX_6 = (uint64_t)0;
                    for (; ; ) {
                        uint8_t tmp_11e00_8 = *(uint8_t*)(RDX_6 + RDI_0);
                        uint32_t tmp_lane_1000007f0_3_30_1 = (uint32_t)tmp_11e00_8;
                        uint64_t tmp_4c780_8 = (uint64_t)(int32_t)RAX_1 * 0x1003f;
                        int32_t tmp_lane_1000007f0_8_32_1 = (int32_t)tmp_4c780_8;
                        uint32_t tmp_lane_1000007f0_10_35_1 = (uint32_t)tmp_lane_1000007f0_8_32_1 + tmp_lane_1000007f0_3_30_1;
                        RAX_1 = (uint64_t)(uint32_t)tmp_lane_1000007f0_10_35_1;
                        RDX_6++;
                        uint64_t tmp_3f080_5 = RCX_2;
                        uint8_t tmp_12800_5 = tmp_3f080_5 != RDX_6;
                        if (!tmp_12800_5) {
                            break;
                        }
                    }
                }
                return RAX_1;
            }
        }
    }
}


uint32_t sym__pearson(uint64_t RDI_0, uint64_t RSI_0)
{
#define _pearson_tab__r2sleigh_addr 0x100001680ULL
    extern char _pearson_tab[];

    /* r2dec proof: no individual construct is marked; 133 source obligations: 106 rendered, 27 elided, 0 refused; 59 statements rendered; 1 data object type refused */
    {
        uint64_t RDX_16;
        uint64_t tmp_70500_1 = RSI_0;
        uint8_t ZF_1 = tmp_70500_1 == 0;
        if (ZF_1) {
            RDX_16 = (uint64_t)0;
        } else {
            uint64_t RCX_1;
            uint64_t RDX_1;
            uint32_t tmp_lane_100001259_4_3_1 = (uint32_t)RSI_0 & 3;
            uint64_t RAX_2 = (uint64_t)(uint32_t)tmp_lane_100001259_4_3_1;
            uint64_t tmp_3ea80_1 = RSI_0;
            if (4 <= tmp_3ea80_1) {
                uint64_t RCX_2;
                uint64_t RDX_2;
                RSI_0 &= (uint64_t)-0x4;
                RCX_2 = (uint64_t)0;
                RDX_2 = (uint64_t)0;
                for (; ; ) {
                    uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_2];
                    uint8_t tmp_lane_100001280_5_12_1 = (uint8_t)((uint8_t)RDX_2 ^ tmp_11e00_2);
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RCX_2 + 1];
                    uint8_t tmp_11e00_4 = *(uint8_t*)((uint64_t)tmp_lane_100001280_5_12_1 + (uint64_t)&_pearson_tab);
                    uint8_t tmp_lane_100001280_19_17_1 = (uint8_t)(tmp_11e00_3 ^ tmp_11e00_4);
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RCX_2 + 2];
                    uint8_t tmp_11e00_6 = *(uint8_t*)((uint64_t)tmp_lane_100001280_19_17_1 + (uint64_t)&_pearson_tab);
                    uint8_t tmp_lane_100001280_2d_1c_1 = (uint8_t)(tmp_11e00_5 ^ tmp_11e00_6);
                    uint8_t tmp_11e00_7 = ((uint8_t*)RDI_0)[RCX_2 + 3];
                    uint8_t tmp_11e00_8 = *(uint8_t*)((uint64_t)tmp_lane_100001280_2d_1c_1 + (uint64_t)&_pearson_tab);
                    uint8_t tmp_lane_100001280_41_21_1 = (uint8_t)(tmp_11e00_7 ^ tmp_11e00_8);
                    uint8_t tmp_11e00_9 = *(uint8_t*)((uint64_t)tmp_lane_100001280_41_21_1 + (uint64_t)&_pearson_tab);
                    RDX_2 = (uint64_t)(uint32_t)tmp_11e00_9;
                    RCX_2 += 4;
                    uint64_t tmp_3f080_2 = RSI_0;
                    uint8_t tmp_12800_2 = tmp_3f080_2 != RCX_2;
                    RCX_1 = RCX_2;
                    RDX_1 = RDX_2;
                    if (!tmp_12800_2) {
                        break;
                    }
                }
            } else {
                RCX_1 = (uint64_t)0;
                RDX_1 = (uint64_t)0;
            }
            {
                uint64_t tmp_70500_2 = RAX_2;
                uint8_t ZF_17 = tmp_70500_2 == 0;
                RDX_16 = RDX_1;
                if (!ZF_17) {
                    uint64_t RCX_6;
                    RDI_0 += RCX_1;
                    RCX_6 = (uint64_t)0;
                    for (; ; ) {
                        uint8_t tmp_11e00_12 = *(uint8_t*)(RCX_6 + RDI_0);
                        uint8_t tmp_lane_1000012d0_5_29_1 = (uint8_t)((uint8_t)RDX_1 ^ tmp_11e00_12);
                        uint8_t tmp_11e00_13 = *(uint8_t*)((uint64_t)tmp_lane_1000012d0_5_29_1 + (uint64_t)&_pearson_tab);
                        RDX_1 = (uint64_t)(uint32_t)tmp_11e00_13;
                        RCX_6++;
                        uint64_t tmp_3f080_5 = RAX_2;
                        uint8_t tmp_12800_5 = tmp_3f080_5 != RCX_6;
                        RDX_16 = RDX_1;
                        if (!tmp_12800_5) {
                            break;
                        }
                    }
                }
            }
        }
        {
            uint32_t tmp_lane_1000012e2_0_31_1 = (uint32_t)(uint8_t)RDX_16;
            return tmp_lane_1000012e2_0_31_1;
        }
    }
}


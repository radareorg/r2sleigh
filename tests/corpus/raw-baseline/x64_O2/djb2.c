uint64_t sym__djb2(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 124 source obligations: 94 rendered, 30 elided, 0 refused; 65 statements rendered */
    {
        uint64_t tmp_70500_1 = RSI_0;
        if (tmp_70500_1 == 0) {
            return 0x1505;
        } else {
            uint64_t RAX_1;
            uint64_t RDX_1;
            uint32_t tmp_lane_1000006c9_4_3_1 = (uint32_t)RSI_0 & 3;
            uint64_t RCX_2 = (uint64_t)(uint32_t)tmp_lane_1000006c9_4_3_1;
            uint64_t tmp_3ea80_1 = RSI_0;
            if (4 <= tmp_3ea80_1) {
                uint64_t RAX_2;
                uint64_t RDX_2;
                RSI_0 &= (uint64_t)-0x4;
                RAX_2 = 0x1505;
                RDX_2 = (uint64_t)0;
                for (; ; ) {
                    uint32_t tmp_lane_1000006f0_0_b_1 = (uint32_t)RAX_2;
                    uint32_t tmp_lane_1000006f0_4_e_1 = tmp_lane_1000006f0_0_b_1 << 5;
                    uint32_t tmp_lane_1000006f0_2a_12_1 = (uint32_t)RAX_2 + tmp_lane_1000006f0_4_e_1;
                    uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RDX_2];
                    uint32_t tmp_lane_1000006f0_39_17_1 = (uint32_t)tmp_11e00_2 + tmp_lane_1000006f0_2a_12_1;
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RDX_2 + 1];
                    uint32_t tmp_lane_1000006f0_45_19_1 = (uint32_t)tmp_11e00_3;
                    uint32_t tmp_lane_1000006f0_49_1c_1 = tmp_lane_1000006f0_45_19_1 + tmp_lane_1000006f0_39_17_1;
                    uint32_t tmp_lane_1000006f0_53_1f_1 = tmp_lane_1000006f0_39_17_1 << 5;
                    uint32_t tmp_lane_1000006f0_79_23_1 = tmp_lane_1000006f0_49_1c_1 + tmp_lane_1000006f0_53_1f_1;
                    uint8_t tmp_11e00_4 = ((uint8_t*)RDI_0)[RDX_2 + 2];
                    uint32_t tmp_lane_1000006f0_85_25_1 = (uint32_t)tmp_11e00_4;
                    uint32_t tmp_lane_1000006f0_89_28_1 = tmp_lane_1000006f0_85_25_1 + tmp_lane_1000006f0_79_23_1;
                    uint32_t tmp_lane_1000006f0_93_2b_1 = tmp_lane_1000006f0_79_23_1 << 5;
                    uint32_t tmp_lane_1000006f0_b9_2f_1 = tmp_lane_1000006f0_89_28_1 + tmp_lane_1000006f0_93_2b_1;
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RDX_2 + 3];
                    uint32_t tmp_lane_1000006f0_c5_31_1 = (uint32_t)tmp_11e00_5;
                    uint32_t tmp_lane_1000006f0_c9_34_1 = tmp_lane_1000006f0_c5_31_1 + tmp_lane_1000006f0_b9_2f_1;
                    uint32_t tmp_lane_1000006f0_d3_37_1 = tmp_lane_1000006f0_b9_2f_1 << 5;
                    uint32_t tmp_lane_1000006f0_f9_3b_1 = tmp_lane_1000006f0_c9_34_1 + tmp_lane_1000006f0_d3_37_1;
                    RAX_2 = (uint64_t)(uint32_t)tmp_lane_1000006f0_f9_3b_1;
                    RDX_2 += 4;
                    uint64_t tmp_3f080_2 = RSI_0;
                    uint8_t ZF_21 = tmp_3f080_2 == RDX_2;
                    uint8_t tmp_12800_2 = !ZF_21;
                    RAX_1 = RAX_2;
                    RDX_1 = RDX_2;
                    if (!tmp_12800_2) {
                        break;
                    }
                }
            } else {
                RAX_1 = 0x1505;
                RDX_1 = (uint64_t)0;
            }
            {
                uint64_t tmp_70500_2 = RCX_2;
                if (tmp_70500_2 != 0) {
                    uint64_t RDX_6;
                    RDI_0 += RDX_1;
                    RDX_6 = (uint64_t)0;
                    for (; ; ) {
                        uint32_t tmp_lane_100000750_0_40_1 = (uint32_t)RAX_1;
                        uint32_t tmp_lane_100000750_4_43_1 = tmp_lane_100000750_0_40_1 << 5;
                        uint32_t tmp_lane_100000750_2a_47_1 = (uint32_t)RAX_1 + tmp_lane_100000750_4_43_1;
                        uint8_t tmp_11e00_8 = *(uint8_t*)(RDX_6 + RDI_0);
                        uint32_t tmp_lane_100000750_39_4c_1 = (uint32_t)tmp_11e00_8 + tmp_lane_100000750_2a_47_1;
                        RAX_1 = (uint64_t)(uint32_t)tmp_lane_100000750_39_4c_1;
                        RDX_6++;
                        uint64_t tmp_3f080_5 = RCX_2;
                        uint8_t ZF_31 = tmp_3f080_5 == RDX_6;
                        uint8_t tmp_12800_5 = !ZF_31;
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


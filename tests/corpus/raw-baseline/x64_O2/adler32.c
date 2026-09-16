uint64_t sym__adler32(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 164 source obligations: 136 rendered, 28 elided, 0 refused; 94 statements rendered */
    {
        uint64_t tmp_70500_1 = RSI_0;
        if (tmp_70500_1 == 0) {
            return 1;
        } else {
            uint64_t RCX_1;
            uint64_t RDX_1;
            uint64_t RAX_1;
            uint64_t tmp_3ea80_1 = RSI_0;
            if (tmp_3ea80_1 != 1) {
                uint64_t RCX_2;
                uint64_t RDX_2;
                uint64_t RAX_2;
                uint64_t R8_2 = RSI_0 & (uint64_t)-0x2;
                RCX_2 = 1;
                RDX_2 = (uint64_t)0;
                RAX_2 = (uint64_t)0;
                for (; ; ) {
                    int64_t RCX_4;
                    int64_t RCX_8;
                    uint64_t R10_5;
                    uint64_t R10_8;
                    uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RDX_2];
                    uint32_t tmp_lane_100000850_7_f_1 = (uint32_t)tmp_11e00_2 + (uint32_t)RCX_2;
                    RCX_4 = (int64_t)tmp_lane_100000850_7_f_1;
                    RCX_4 = (int64_t)((uint64_t)RCX_4 * 0x80078071);
                    RCX_4 = (int64_t)((uint64_t)RCX_4 >> 47);
                    uint64_t tmp_4c780_2 = (uint64_t)(int32_t)RCX_4 * 0xfff1;
                    int32_t tmp_lane_100000850_40_12_1 = (int32_t)tmp_4c780_2;
                    uint32_t tmp_lane_100000850_48_15_1 = tmp_lane_100000850_7_f_1 - (uint32_t)tmp_lane_100000850_40_12_1;
                    uint32_t tmp_lane_100000850_52_19_1 = (uint32_t)RAX_2 + tmp_lane_100000850_48_15_1;
                    RCX_8 = (int64_t)tmp_lane_100000850_52_19_1;
                    RCX_8 = (int64_t)((uint64_t)RCX_8 * 0x80078071);
                    RCX_8 = (int64_t)((uint64_t)RCX_8 >> 47);
                    uint64_t tmp_4c780_3 = (uint64_t)(int32_t)RCX_8 * 0xfff1;
                    int32_t tmp_lane_100000850_8b_1c_1 = (int32_t)tmp_4c780_3;
                    uint32_t tmp_lane_100000850_93_1f_1 = tmp_lane_100000850_52_19_1 - (uint32_t)tmp_lane_100000850_8b_1c_1;
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RDX_2 + 1];
                    uint32_t tmp_lane_100000850_a3_24_1 = (uint32_t)tmp_11e00_3 + tmp_lane_100000850_48_15_1;
                    int64_t RCX_13 = (int64_t)(uint32_t)tmp_lane_100000850_a3_24_1;
                    R10_5 = (uint64_t)RCX_13 * 0x2001f;
                    R10_5 >>= 33;
                    uint64_t tmp_4c780_4 = (uint64_t)(int32_t)R10_5 * 0xfff1;
                    int32_t tmp_lane_100000850_dc_27_1 = (int32_t)tmp_4c780_4;
                    uint32_t tmp_lane_100000850_e4_2a_1 = tmp_lane_100000850_a3_24_1 - (uint32_t)tmp_lane_100000850_dc_27_1;
                    RCX_2 = (uint64_t)(uint32_t)tmp_lane_100000850_e4_2a_1;
                    uint32_t tmp_lane_100000850_ee_2e_1 = tmp_lane_100000850_93_1f_1 + tmp_lane_100000850_e4_2a_1;
                    int64_t RAX_6 = (int64_t)(uint32_t)tmp_lane_100000850_ee_2e_1;
                    R10_8 = (uint64_t)RAX_6 * 0x2001f;
                    R10_8 >>= 33;
                    uint64_t tmp_4c780_5 = (uint64_t)(int32_t)R10_8 * 0xfff1;
                    int32_t tmp_lane_100000850_127_31_1 = (int32_t)tmp_4c780_5;
                    uint32_t tmp_lane_100000850_12f_34_1 = tmp_lane_100000850_ee_2e_1 - (uint32_t)tmp_lane_100000850_127_31_1;
                    RAX_2 = (uint64_t)(uint32_t)tmp_lane_100000850_12f_34_1;
                    RDX_2 += 2;
                    uint64_t tmp_3f080_2 = R8_2;
                    uint8_t tmp_12800_3 = tmp_3f080_2 != RDX_2;
                    RAX_1 = RAX_2;
                    RCX_1 = RCX_2;
                    RDX_1 = RDX_2;
                    if (!tmp_12800_3) {
                        break;
                    }
                }
            } else {
                RCX_1 = 1;
                RDX_1 = (uint64_t)0;
                RAX_1 = (uint64_t)0;
            }
            {
                uint64_t RCX_17;
                uint64_t RAX_10;
                uint8_t tmp_6fe00_1 = (uint8_t)((uint8_t)RSI_0 & 1);
                uint8_t ZF_24 = tmp_6fe00_1 == 0;
                RAX_10 = RAX_1;
                RCX_17 = RCX_1;
                if (!ZF_24) {
                    int64_t RDX_7;
                    int64_t RSI_1;
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RDX_1];
                    uint32_t tmp_lane_1000008c5_7_3a_1 = (uint32_t)tmp_11e00_5 + (uint32_t)RCX_1;
                    RDX_7 = 0x80078071;
                    RSI_1 = (int64_t)tmp_lane_1000008c5_7_3a_1;
                    RSI_1 = (int64_t)((uint64_t)RSI_1 * (uint64_t)RDX_7);
                    RSI_1 = (int64_t)((uint64_t)RSI_1 >> 47);
                    uint64_t tmp_4c780_7 = (uint64_t)(int32_t)RSI_1 * 0xfff1;
                    int32_t tmp_lane_1000008c5_41_3d_1 = (int32_t)tmp_4c780_7;
                    uint32_t tmp_lane_1000008c5_49_40_1 = tmp_lane_1000008c5_7_3a_1 - (uint32_t)tmp_lane_1000008c5_41_3d_1;
                    RCX_17 = (uint64_t)(uint32_t)tmp_lane_1000008c5_49_40_1;
                    uint32_t tmp_lane_1000008c5_53_44_1 = (uint32_t)RAX_1 + tmp_lane_1000008c5_49_40_1;
                    int64_t RAX_9 = (int64_t)(uint32_t)tmp_lane_1000008c5_53_44_1;
                    RDX_7 = (int64_t)((uint64_t)RDX_7 * (uint64_t)RAX_9);
                    RDX_7 = (int64_t)((uint64_t)RDX_7 >> 47);
                    uint64_t tmp_4c780_8 = (uint64_t)(int32_t)RDX_7 * 0xfff1;
                    int32_t tmp_lane_1000008c5_8b_47_1 = (int32_t)tmp_4c780_8;
                    uint32_t tmp_lane_1000008c5_93_4a_1 = tmp_lane_1000008c5_53_44_1 - (uint32_t)tmp_lane_1000008c5_8b_47_1;
                    RAX_10 = (uint64_t)(uint32_t)tmp_lane_1000008c5_93_4a_1;
                }
                {
                    uint32_t tmp_lane_1000008f5_1_4c_1 = (uint32_t)RAX_10;
                    uint32_t tmp_lane_1000008f5_2_4d_1 = tmp_lane_1000008f5_1_4c_1 << 16;
                    uint32_t tmp_lane_1000008f5_28_51_1 = (uint32_t)RCX_17 | tmp_lane_1000008f5_2_4d_1;
                    return (uint64_t)tmp_lane_1000008f5_28_51_1;
                }
            }
        }
    }
}


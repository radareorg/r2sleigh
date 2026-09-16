uint32_t sym__crc32_bitwise(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 321 source obligations: 301 rendered, 20 elided, 0 refused; 81 statements rendered */
    {
        uint64_t tmp_70500_1 = RSI_0;
        if (tmp_70500_1 == 0) {
            return 0;
        } else {
            uint64_t RAX_1;
            uint64_t RCX_1;
            __uint128_t XMM3_6;
            uint32_t tmp_lane_100000a50_267_74_1;
            RAX_1 = 0xffffffff;
            RCX_1 = (uint64_t)0;
            __uint128_t XMM0_1 = *(__uint128_t*)0x1000015e0;
            __uint128_t XMM1_1 = *(__uint128_t*)0x1000015f0;
            XMM3_6 = 0;
            for (; ; ) {
                __uint128_t XMM2_17;
                __uint128_t XMM2_2;
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                uint32_t tmp_lane_100000a50_7_6_1 = (uint32_t)tmp_11e00_2 ^ (uint32_t)RAX_1;
                uint32_t tmp_lane_100000a50_14_b_1 = tmp_lane_100000a50_7_6_1 >> 1;
                uint32_t tmp_lane_100000a50_20_10_1 = tmp_lane_100000a50_7_6_1 & 1;
                uint32_t tmp_lane_100000a50_2a_13_1 = -tmp_lane_100000a50_20_10_1;
                uint32_t tmp_lane_100000a50_34_15_1 = tmp_lane_100000a50_2a_13_1 & 0xedb88320;
                uint32_t tmp_lane_100000a50_3e_19_1 = tmp_lane_100000a50_34_15_1 ^ tmp_lane_100000a50_14_b_1;
                uint32_t tmp_lane_100000a50_4b_1e_1 = tmp_lane_100000a50_3e_19_1 >> 1;
                XMM2_2 = (__uint128_t)(uint32_t)tmp_lane_100000a50_7_6_1;
                int32_t tmp_lane_100000a50_56_22_1 = (int32_t)(tmp_lane_100000a50_7_6_1 << 30);
                uint32_t tmp_lane_100000a50_7c_25_1 = (uint32_t)(tmp_lane_100000a50_56_22_1 >> 31);
                uint32_t tmp_lane_100000a50_9f_28_1 = tmp_lane_100000a50_7c_25_1 & 0xedb88320;
                uint32_t tmp_lane_100000a50_a9_2c_1 = tmp_lane_100000a50_9f_28_1 ^ tmp_lane_100000a50_4b_1e_1;
                uint32_t tmp_lane_100000a50_b5_31_1 = tmp_lane_100000a50_a9_2c_1 >> 6;
                uint32_t tmp_c1380_2 = tmp_lane_100000a50_7_6_1;
                XMM2_2 = (XMM2_2 & ~((__uint128_t)~(uint32_t)0U << 0U)) | (__uint128_t)tmp_c1380_2 << 0;
                XMM2_2 = (XMM2_2 & ~((__uint128_t)~(uint32_t)0U << 32U)) | (__uint128_t)tmp_c1380_2 << 32;
                XMM2_2 = (XMM2_2 & ~((__uint128_t)~(uint32_t)0U << 64U)) | (__uint128_t)tmp_c1380_2 << 64;
                XMM2_2 = (XMM2_2 & ~((__uint128_t)~(uint32_t)0U << 96U)) | (__uint128_t)tmp_c1380_2 << 96;
                XMM2_2 &= XMM0_1;
                uint32_t tmp_lane_100000a50_11a_3b_1 = (uint32_t)XMM2_2;
                uint32_t tmp_lane_100000a50_11a_3c_1 = (uint32_t)XMM0_1;
                XMM2_17 = (XMM2_2 & ~((__uint128_t)~(uint32_t)0U << 0U)) | (__uint128_t)((uint32_t)(tmp_lane_100000a50_11a_3b_1 == tmp_lane_100000a50_11a_3c_1) * 0xffffffff) << 0;
                uint32_t tmp_lane_100000a50_11d_3e_1 = (uint32_t)(XMM2_2 >> 32);
                uint32_t tmp_lane_100000a50_11d_3f_1 = (uint32_t)(XMM0_1 >> 32);
                XMM2_17 = (XMM2_17 & ~((__uint128_t)~(uint32_t)0U << 32U)) | (__uint128_t)((uint32_t)(tmp_lane_100000a50_11d_3e_1 == tmp_lane_100000a50_11d_3f_1) * 0xffffffff) << 32;
                uint32_t tmp_lane_100000a50_120_41_1 = (uint32_t)(XMM2_2 >> 64);
                uint32_t tmp_lane_100000a50_120_42_1 = (uint32_t)(XMM0_1 >> 64);
                XMM2_17 = (XMM2_17 & ~((__uint128_t)~(uint32_t)0U << 64U)) | (__uint128_t)((uint32_t)(tmp_lane_100000a50_120_41_1 == tmp_lane_100000a50_120_42_1) * 0xffffffff) << 64;
                uint32_t tmp_lane_100000a50_123_44_1 = (uint32_t)(XMM2_2 >> 96);
                uint32_t tmp_lane_100000a50_123_45_1 = (uint32_t)(XMM0_1 >> 96);
                XMM2_17 = (XMM2_17 & ~((__uint128_t)~(uint32_t)0U << 96U)) | (__uint128_t)((uint32_t)(tmp_lane_100000a50_123_44_1 == tmp_lane_100000a50_123_45_1) * 0xffffffff) << 96;
                XMM2_17 &= XMM1_1;
                int32_t tmp_lane_100000a50_129_48_1 = (int32_t)(tmp_lane_100000a50_3e_19_1 << 26);
                uint32_t tmp_lane_100000a50_14f_4b_1 = (uint32_t)(tmp_lane_100000a50_129_48_1 >> 31);
                uint32_t tmp_lane_100000a50_172_4e_1 = tmp_lane_100000a50_14f_4b_1 & 0x76dc4190;
                int32_t tmp_lane_100000a50_17c_51_1 = (int32_t)(tmp_lane_100000a50_a9_2c_1 << 26);
                uint32_t tmp_lane_100000a50_1a2_54_1 = (uint32_t)(tmp_lane_100000a50_17c_51_1 >> 31);
                uint32_t tmp_lane_100000a50_1c5_57_1 = tmp_lane_100000a50_1a2_54_1 & 0xedb88320;
                uint32_t tmp_lane_100000a50_1cf_5b_1 = tmp_lane_100000a50_1c5_57_1 ^ tmp_lane_100000a50_b5_31_1;
                uint32_t tmp_lane_100000a50_1d9_5f_1 = tmp_lane_100000a50_1cf_5b_1 ^ tmp_lane_100000a50_172_4e_1;
                uint32_t tmp_lane_100000a50_1e3_63_1 = (uint32_t)(XMM2_17 >> 64);
                uint32_t tmp_c1480_3 = tmp_lane_100000a50_1e3_63_1;
                uint32_t tmp_lane_100000a50_1e4_64_1 = (uint32_t)(XMM2_17 >> 96);
                uint32_t tmp_c1500_3 = tmp_lane_100000a50_1e4_64_1;
                XMM3_6 = (XMM3_6 & ~((__uint128_t)~(uint32_t)0U << 0U)) | (__uint128_t)tmp_c1480_3 << 0;
                XMM3_6 = (XMM3_6 & ~((__uint128_t)~(uint32_t)0U << 32U)) | (__uint128_t)tmp_c1500_3 << 32;
                XMM3_6 = (XMM3_6 & ~((__uint128_t)~(uint32_t)0U << 64U)) | (__uint128_t)tmp_c1480_3 << 64;
                XMM3_6 = (XMM3_6 & ~((__uint128_t)~(uint32_t)0U << 96U)) | (__uint128_t)tmp_c1500_3 << 96;
                XMM3_6 ^= XMM2_17;
                uint32_t tmp_lane_100000a50_223_6a_1 = (uint32_t)(XMM3_6 >> 32);
                uint32_t tmp_c1400_4 = tmp_lane_100000a50_223_6a_1;
                XMM2_17 = (XMM2_17 & ~((__uint128_t)~(uint32_t)0U << 0U)) | (__uint128_t)tmp_c1400_4 << 0;
                XMM2_17 = (XMM2_17 & ~((__uint128_t)~(uint32_t)0U << 32U)) | (__uint128_t)tmp_c1400_4 << 32;
                XMM2_17 = (XMM2_17 & ~((__uint128_t)~(uint32_t)0U << 64U)) | (__uint128_t)tmp_c1400_4 << 64;
                XMM2_17 = (XMM2_17 & ~((__uint128_t)~(uint32_t)0U << 96U)) | (__uint128_t)tmp_c1400_4 << 96;
                XMM2_17 ^= XMM3_6;
                uint32_t tmp_lane_100000a50_263_71_1 = (uint32_t)XMM2_17;
                tmp_lane_100000a50_267_74_1 = tmp_lane_100000a50_263_71_1 ^ tmp_lane_100000a50_1d9_5f_1;
                RAX_1 = (uint64_t)(uint32_t)tmp_lane_100000a50_267_74_1;
                RCX_1++;
                uint64_t tmp_3f080_2 = RSI_0;
                uint8_t tmp_12800_2 = tmp_3f080_2 != RCX_1;
                if (!tmp_12800_2) {
                    break;
                }
            }
            return ~tmp_lane_100000a50_267_74_1;
        }
    }
}


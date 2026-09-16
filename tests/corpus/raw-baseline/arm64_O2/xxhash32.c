struct r2sleigh_bits_256 {
    uint8_t bytes[32];
};

uint32_t sym__xxhash32(uint64_t X0_0, uint64_t X1_0, uint32_t W2_0)
{
    /* r2dec proof: no individual construct is marked; 420 source obligations: 391 rendered, 29 elided, 0 refused; 231 statements rendered */
    {
        struct r2sleigh_bits_256 Z0_1;
        struct r2sleigh_bits_256 Z1_1;
        uint64_t X11_8;
        uint64_t X12_4;
        Z0_1 = r2sleigh_bits_zero_extend_64_256(0U);
        Z1_1 = r2sleigh_bits_zero_extend_64_256(0U);
        uint32_t tmp_2a000_2 = 0x165667b1;
        uint64_t X9_1 = X1_0 + X0_0;
        if (X1_0 < 16) {
            X11_8 = (uint64_t)(uint32_t)(tmp_2a000_2 + W2_0);
            X12_4 = X0_0;
        } else {
            uint64_t X12_1;
            uint32_t tmp_lane_1000009ac_21_6f_1;
            uint32_t tmp_lane_1000009ac_22_72_1;
            uint32_t tmp_lane_1000009ac_23_75_1;
            uint32_t tmp_lane_1000009ac_24_78_1;
            uint64_t X10_1 = X9_1 - 16;
            Z1_1 = r2sleigh_bits_insert_256_32(Z1_1, W2_0, 64);
            Z1_1 = r2sleigh_bits_insert_256_64(Z1_1, 0, 128);
            Z1_1 = r2sleigh_bits_insert_256_64(Z1_1, 0, 192);
            Z1_1 = r2sleigh_bits_insert_256_32(Z1_1, W2_0 + 0x61c8864f, 96);
            uint32_t tmp_lane_100000964_12_c_1 = W2_0;
            Z0_1 = r2sleigh_bits_insert_256_32(Z0_1, tmp_lane_100000964_12_c_1, 0);
            Z0_1 = r2sleigh_bits_insert_256_32(Z0_1, tmp_lane_100000964_12_c_1, 32);
            Z0_1 = r2sleigh_bits_insert_256_32(Z0_1, tmp_lane_100000964_12_c_1, 64);
            Z0_1 = r2sleigh_bits_insert_256_32(Z0_1, tmp_lane_100000964_12_c_1, 96);
            Z0_1 = r2sleigh_bits_insert_256_64(Z0_1, 0, 128);
            Z0_1 = r2sleigh_bits_insert_256_64(Z0_1, 0, 192);
            __uint128_t tmp_lane_100000964_1a_13_1 = *(__uint128_t*)0x100001010;
            uint32_t tmp_lane_100000964_1d_17_1 = (uint32_t)tmp_lane_100000964_1a_13_1;
            Z0_1 = r2sleigh_bits_insert_256_32(Z0_1, tmp_lane_100000964_12_c_1 + tmp_lane_100000964_1d_17_1, 0);
            uint32_t tmp_lane_100000964_1e_1a_1 = (uint32_t)(tmp_lane_100000964_1a_13_1 >> 32);
            Z0_1 = r2sleigh_bits_insert_256_32(Z0_1, tmp_lane_100000964_12_c_1 + tmp_lane_100000964_1e_1a_1, 32);
            uint32_t tmp_lane_100000964_1f_1d_1 = (uint32_t)(tmp_lane_100000964_1a_13_1 >> 64);
            Z0_1 = r2sleigh_bits_insert_256_32(Z0_1, tmp_lane_100000964_12_c_1 + tmp_lane_100000964_1f_1d_1, 64);
            uint32_t tmp_lane_100000964_20_20_1 = (uint32_t)(tmp_lane_100000964_1a_13_1 >> 96);
            Z0_1 = r2sleigh_bits_insert_256_32(Z0_1, tmp_lane_100000964_12_c_1 + tmp_lane_100000964_20_20_1, 96);
            Z0_1 = r2sleigh_bits_insert_256_64(Z0_1, 0, 128);
            Z0_1 = r2sleigh_bits_insert_256_64(Z0_1, 0, 192);
            uint64_t tmp_lane_100000964_23_24_1 = r2sleigh_bits_extract_256_64(Z1_1, 64U);
            Z0_1 = r2sleigh_bits_insert_256_64(Z0_1, tmp_lane_100000964_23_24_1, 64);
            Z0_1 = r2sleigh_bits_insert_256_64(Z0_1, 0, 128);
            Z0_1 = r2sleigh_bits_insert_256_64(Z0_1, 0, 192);
            uint32_t tmp_2a000_6 = 0x85ebca77;
            uint32_t tmp_2a000_8 = 0x9e3779b1;
            X11_8 = (uint64_t)(uint32_t)tmp_2a000_8;
            X12_1 = X0_0;
            for (; ; ) {
                struct r2sleigh_bits_256 Z0_17;
                uint64_t tmp_7400_2 = X12_1;
                X12_1 += 16;
                __uint128_t tmp_lane_1000009ac_2_38_1 = *(__uint128_t*)tmp_7400_2;
                uint32_t tmp_lane_1000009ac_5_3b_1 = (uint32_t)tmp_lane_1000009ac_2_38_1;
                uint32_t tmp_lane_1000009ac_6_3e_1 = (uint32_t)(tmp_lane_1000009ac_2_38_1 >> 32);
                uint32_t tmp_lane_1000009ac_7_41_1 = (uint32_t)(tmp_lane_1000009ac_2_38_1 >> 64);
                uint32_t tmp_lane_1000009ac_8_44_1 = (uint32_t)(tmp_lane_1000009ac_2_38_1 >> 96);
                uint32_t tmp_lane_1000009ac_9_47_1 = r2sleigh_bits_extract_256_32(Z0_1, 0U);
                uint32_t tmp_lane_1000009ac_9_48_1 = tmp_lane_1000009ac_5_3b_1 * tmp_2a000_6 + tmp_lane_1000009ac_9_47_1;
                Z0_17 = r2sleigh_bits_insert_256_32(Z0_1, tmp_lane_1000009ac_9_48_1, 0);
                uint32_t tmp_lane_1000009ac_a_49_1 = r2sleigh_bits_extract_256_32(Z0_1, 32U);
                uint32_t tmp_lane_1000009ac_a_4a_1 = tmp_lane_1000009ac_6_3e_1 * tmp_2a000_6 + tmp_lane_1000009ac_a_49_1;
                Z0_17 = r2sleigh_bits_insert_256_32(Z0_17, tmp_lane_1000009ac_a_4a_1, 32);
                uint32_t tmp_lane_1000009ac_b_4b_1 = r2sleigh_bits_extract_256_32(Z0_1, 64U);
                uint32_t tmp_lane_1000009ac_b_4c_1 = tmp_lane_1000009ac_7_41_1 * tmp_2a000_6 + tmp_lane_1000009ac_b_4b_1;
                Z0_17 = r2sleigh_bits_insert_256_32(Z0_17, tmp_lane_1000009ac_b_4c_1, 64);
                uint32_t tmp_lane_1000009ac_c_4d_1 = r2sleigh_bits_extract_256_32(Z0_1, 96U);
                uint32_t tmp_lane_1000009ac_c_4e_1 = tmp_lane_1000009ac_8_44_1 * tmp_2a000_6 + tmp_lane_1000009ac_c_4d_1;
                Z0_17 = r2sleigh_bits_insert_256_32(Z0_17, tmp_lane_1000009ac_c_4e_1, 96);
                Z0_17 = r2sleigh_bits_insert_256_64(Z0_17, 0, 128);
                Z0_17 = r2sleigh_bits_insert_256_64(Z0_17, 0, 192);
                tmp_lane_1000009ac_21_6f_1 = tmp_2a000_8 * ((tmp_lane_1000009ac_9_48_1 >> 19) + tmp_lane_1000009ac_9_48_1 * 0x2000);
                Z0_17 = r2sleigh_bits_insert_256_32(Z0_17, tmp_lane_1000009ac_21_6f_1, 0);
                tmp_lane_1000009ac_22_72_1 = tmp_2a000_8 * ((tmp_lane_1000009ac_a_4a_1 >> 19) + tmp_lane_1000009ac_a_4a_1 * 0x2000);
                Z0_17 = r2sleigh_bits_insert_256_32(Z0_17, tmp_lane_1000009ac_22_72_1, 32);
                tmp_lane_1000009ac_23_75_1 = tmp_2a000_8 * ((tmp_lane_1000009ac_b_4c_1 >> 19) + tmp_lane_1000009ac_b_4c_1 * 0x2000);
                Z0_17 = r2sleigh_bits_insert_256_32(Z0_17, tmp_lane_1000009ac_23_75_1, 64);
                tmp_lane_1000009ac_24_78_1 = tmp_2a000_8 * ((tmp_lane_1000009ac_c_4e_1 >> 19) + tmp_lane_1000009ac_c_4e_1 * 0x2000);
                Z0_17 = r2sleigh_bits_insert_256_32(Z0_17, tmp_lane_1000009ac_24_78_1, 96);
                Z0_1 = r2sleigh_bits_insert_256_64(Z0_17, 0, 128);
                Z0_1 = r2sleigh_bits_insert_256_64(Z0_1, 0, 192);
                uint8_t tmp_1000_2 = X12_1 <= X10_1;
                if (!tmp_1000_2) {
                    break;
                }
            }
            {
                struct r2sleigh_bits_256 Z0_34;
                struct r2sleigh_bits_256 Z0_38;
                struct r2sleigh_bits_256 Z0_42;
                __uint128_t tmp_lane_1000009c8_2_7b_1 = *(__uint128_t*)0x100001020;
                uint32_t tmp_0_1 = tmp_lane_1000009ac_21_6f_1;
                int8_t tmp_8_1 = (int8_t)tmp_lane_1000009c8_2_7b_1;
                uint32_t tmp_9_1 = (uint32_t)(int8_t)tmp_8_1;
                uint8_t tmp_d_1 = (int32_t)tmp_9_1 < 0;
                uint32_t tmp_e_1 = -tmp_9_1;
                uint32_t tmp_27_1 = tmp_lane_1000009ac_22_72_1;
                int8_t tmp_2f_1 = (int8_t)(tmp_lane_1000009c8_2_7b_1 >> 32);
                uint32_t tmp_30_1 = (uint32_t)(int8_t)tmp_2f_1;
                uint8_t tmp_34_1 = (int32_t)tmp_30_1 < 0;
                uint32_t tmp_35_1 = -tmp_30_1;
                uint32_t tmp_4e_1 = tmp_lane_1000009ac_23_75_1;
                int8_t tmp_56_1 = (int8_t)(tmp_lane_1000009c8_2_7b_1 >> 64);
                uint32_t tmp_57_1 = (uint32_t)(int8_t)tmp_56_1;
                uint8_t tmp_5b_1 = (int32_t)tmp_57_1 < 0;
                uint32_t tmp_5c_1 = -tmp_57_1;
                uint32_t tmp_75_1 = tmp_lane_1000009ac_24_78_1;
                int8_t tmp_7d_1 = (int8_t)(tmp_lane_1000009c8_2_7b_1 >> 96);
                uint32_t tmp_7e_1 = (uint32_t)(int8_t)tmp_7d_1;
                uint8_t tmp_82_1 = (int32_t)tmp_7e_1 < 0;
                uint32_t tmp_83_1 = -tmp_7e_1;
                __uint128_t tmp_ac_1 = (__uint128_t)((uint64_t)((tmp_82_1 ? tmp_83_1 : tmp_7e_1) < 32 ? tmp_82_1 ? tmp_75_1 >> tmp_83_1 : tmp_75_1 << tmp_7e_1 : 0) << 32 | (uint64_t)((tmp_5b_1 ? tmp_5c_1 : tmp_57_1) < 32 ? tmp_5b_1 ? tmp_4e_1 >> tmp_5c_1 : tmp_4e_1 << tmp_57_1 : 0)) << 64 | (__uint128_t)((uint64_t)((tmp_34_1 ? tmp_35_1 : tmp_30_1) < 32 ? tmp_34_1 ? tmp_27_1 >> tmp_35_1 : tmp_27_1 << tmp_30_1 : 0) << 32 | (uint64_t)((tmp_d_1 ? tmp_e_1 : tmp_9_1) < 32 ? tmp_d_1 ? tmp_0_1 >> tmp_e_1 : tmp_0_1 << tmp_9_1 : 0));
                __uint128_t tmp_lane_1000009c8_3b_81_1 = *(__uint128_t*)0x100001030;
                uint32_t tmp_0_2 = tmp_lane_1000009ac_21_6f_1;
                int8_t tmp_8_2 = (int8_t)tmp_lane_1000009c8_3b_81_1;
                uint32_t tmp_9_2 = (uint32_t)(int8_t)tmp_8_2;
                uint8_t tmp_d_2 = (int32_t)tmp_9_2 < 0;
                uint32_t tmp_e_2 = -tmp_9_2;
                uint32_t tmp_27_2 = tmp_lane_1000009ac_22_72_1;
                int8_t tmp_2f_2 = (int8_t)(tmp_lane_1000009c8_3b_81_1 >> 32);
                uint32_t tmp_30_2 = (uint32_t)(int8_t)tmp_2f_2;
                uint8_t tmp_34_2 = (int32_t)tmp_30_2 < 0;
                uint32_t tmp_35_2 = -tmp_30_2;
                uint32_t tmp_4e_2 = tmp_lane_1000009ac_23_75_1;
                int8_t tmp_56_2 = (int8_t)(tmp_lane_1000009c8_3b_81_1 >> 64);
                uint32_t tmp_57_2 = (uint32_t)(int8_t)tmp_56_2;
                uint8_t tmp_5b_2 = (int32_t)tmp_57_2 < 0;
                uint32_t tmp_5c_2 = -tmp_57_2;
                uint32_t tmp_75_2 = tmp_lane_1000009ac_24_78_1;
                int8_t tmp_7d_2 = (int8_t)(tmp_lane_1000009c8_3b_81_1 >> 96);
                uint32_t tmp_7e_2 = (uint32_t)(int8_t)tmp_7d_2;
                uint8_t tmp_82_2 = (int32_t)tmp_7e_2 < 0;
                uint32_t tmp_83_2 = -tmp_7e_2;
                __uint128_t tmp_ac_2 = (__uint128_t)((uint64_t)((tmp_82_2 ? tmp_83_2 : tmp_7e_2) < 32 ? tmp_82_2 ? tmp_75_2 >> tmp_83_2 : tmp_75_2 << tmp_7e_2 : 0) << 32 | (uint64_t)((tmp_5b_2 ? tmp_5c_2 : tmp_57_2) < 32 ? tmp_5b_2 ? tmp_4e_2 >> tmp_5c_2 : tmp_4e_2 << tmp_57_2 : 0)) << 64 | (__uint128_t)((uint64_t)((tmp_34_2 ? tmp_35_2 : tmp_30_2) < 32 ? tmp_34_2 ? tmp_27_2 >> tmp_35_2 : tmp_27_2 << tmp_30_2 : 0) << 32 | (uint64_t)((tmp_d_2 ? tmp_e_2 : tmp_9_2) < 32 ? tmp_d_2 ? tmp_0_2 >> tmp_e_2 : tmp_0_2 << tmp_9_2 : 0));
                Z0_1 = r2sleigh_bits_insert_256_128(Z0_1, tmp_ac_2, 0);
                uint8_t tmp_lane_1000009c8_72_87_1 = (uint8_t)tmp_ac_2;
                uint8_t tmp_lane_1000009c8_72_88_1 = (uint8_t)tmp_ac_1;
                Z0_1 = r2sleigh_bits_insert_256_8(Z0_1, (uint8_t)(tmp_lane_1000009c8_72_87_1 | tmp_lane_1000009c8_72_88_1), 0);
                uint8_t tmp_lane_1000009c8_73_8a_1 = (uint8_t)(tmp_ac_2 >> 8);
                uint8_t tmp_lane_1000009c8_73_8b_1 = (uint8_t)(tmp_ac_1 >> 8);
                Z0_1 = r2sleigh_bits_insert_256_8(Z0_1, (uint8_t)(tmp_lane_1000009c8_73_8a_1 | tmp_lane_1000009c8_73_8b_1), 8);
                uint8_t tmp_lane_1000009c8_74_8d_1 = (uint8_t)(tmp_ac_2 >> 16);
                uint8_t tmp_lane_1000009c8_74_8e_1 = (uint8_t)(tmp_ac_1 >> 16);
                Z0_1 = r2sleigh_bits_insert_256_8(Z0_1, (uint8_t)(tmp_lane_1000009c8_74_8d_1 | tmp_lane_1000009c8_74_8e_1), 16);
                uint8_t tmp_lane_1000009c8_75_90_1 = (uint8_t)(tmp_ac_2 >> 24);
                uint8_t tmp_lane_1000009c8_75_91_1 = (uint8_t)(tmp_ac_1 >> 24);
                Z0_1 = r2sleigh_bits_insert_256_8(Z0_1, (uint8_t)(tmp_lane_1000009c8_75_90_1 | tmp_lane_1000009c8_75_91_1), 24);
                uint8_t tmp_lane_1000009c8_76_93_1 = (uint8_t)(tmp_ac_2 >> 32);
                uint8_t tmp_lane_1000009c8_76_94_1 = (uint8_t)(tmp_ac_1 >> 32);
                Z0_34 = r2sleigh_bits_insert_256_8(Z0_1, (uint8_t)(tmp_lane_1000009c8_76_93_1 | tmp_lane_1000009c8_76_94_1), 32);
                uint8_t tmp_lane_1000009c8_77_96_1 = (uint8_t)(tmp_ac_2 >> 40);
                uint8_t tmp_lane_1000009c8_77_97_1 = (uint8_t)(tmp_ac_1 >> 40);
                Z0_34 = r2sleigh_bits_insert_256_8(Z0_34, (uint8_t)(tmp_lane_1000009c8_77_96_1 | tmp_lane_1000009c8_77_97_1), 40);
                uint8_t tmp_lane_1000009c8_78_99_1 = (uint8_t)(tmp_ac_2 >> 48);
                uint8_t tmp_lane_1000009c8_78_9a_1 = (uint8_t)(tmp_ac_1 >> 48);
                Z0_34 = r2sleigh_bits_insert_256_8(Z0_34, (uint8_t)(tmp_lane_1000009c8_78_99_1 | tmp_lane_1000009c8_78_9a_1), 48);
                uint8_t tmp_lane_1000009c8_79_9c_1 = (uint8_t)(tmp_ac_2 >> 56);
                uint8_t tmp_lane_1000009c8_79_9d_1 = (uint8_t)(tmp_ac_1 >> 56);
                Z0_34 = r2sleigh_bits_insert_256_8(Z0_34, (uint8_t)(tmp_lane_1000009c8_79_9c_1 | tmp_lane_1000009c8_79_9d_1), 56);
                uint8_t tmp_lane_1000009c8_7a_9f_1 = (uint8_t)(tmp_ac_2 >> 64);
                uint8_t tmp_lane_1000009c8_7a_a0_1 = (uint8_t)(tmp_ac_1 >> 64);
                Z0_38 = r2sleigh_bits_insert_256_8(Z0_34, (uint8_t)(tmp_lane_1000009c8_7a_9f_1 | tmp_lane_1000009c8_7a_a0_1), 64);
                uint8_t tmp_lane_1000009c8_7b_a2_1 = (uint8_t)(tmp_ac_2 >> 72);
                uint8_t tmp_lane_1000009c8_7b_a3_1 = (uint8_t)(tmp_ac_1 >> 72);
                Z0_38 = r2sleigh_bits_insert_256_8(Z0_38, (uint8_t)(tmp_lane_1000009c8_7b_a2_1 | tmp_lane_1000009c8_7b_a3_1), 72);
                uint8_t tmp_lane_1000009c8_7c_a5_1 = (uint8_t)(tmp_ac_2 >> 80);
                uint8_t tmp_lane_1000009c8_7c_a6_1 = (uint8_t)(tmp_ac_1 >> 80);
                Z0_38 = r2sleigh_bits_insert_256_8(Z0_38, (uint8_t)(tmp_lane_1000009c8_7c_a5_1 | tmp_lane_1000009c8_7c_a6_1), 80);
                uint8_t tmp_lane_1000009c8_7d_a8_1 = (uint8_t)(tmp_ac_2 >> 88);
                uint8_t tmp_lane_1000009c8_7d_a9_1 = (uint8_t)(tmp_ac_1 >> 88);
                Z0_38 = r2sleigh_bits_insert_256_8(Z0_38, (uint8_t)(tmp_lane_1000009c8_7d_a8_1 | tmp_lane_1000009c8_7d_a9_1), 88);
                uint8_t tmp_lane_1000009c8_7e_ab_1 = (uint8_t)(tmp_ac_2 >> 96);
                uint8_t tmp_lane_1000009c8_7e_ac_1 = (uint8_t)(tmp_ac_1 >> 96);
                Z0_42 = r2sleigh_bits_insert_256_8(Z0_38, (uint8_t)(tmp_lane_1000009c8_7e_ab_1 | tmp_lane_1000009c8_7e_ac_1), 96);
                uint8_t tmp_lane_1000009c8_7f_ae_1 = (uint8_t)(tmp_ac_2 >> 104);
                uint8_t tmp_lane_1000009c8_7f_af_1 = (uint8_t)(tmp_ac_1 >> 104);
                Z0_42 = r2sleigh_bits_insert_256_8(Z0_42, (uint8_t)(tmp_lane_1000009c8_7f_ae_1 | tmp_lane_1000009c8_7f_af_1), 104);
                uint8_t tmp_lane_1000009c8_80_b1_1 = (uint8_t)(tmp_ac_2 >> 112);
                uint8_t tmp_lane_1000009c8_80_b2_1 = (uint8_t)(tmp_ac_1 >> 112);
                Z0_42 = r2sleigh_bits_insert_256_8(Z0_42, (uint8_t)(tmp_lane_1000009c8_80_b1_1 | tmp_lane_1000009c8_80_b2_1), 112);
                uint8_t tmp_lane_1000009c8_81_b4_1 = (uint8_t)(tmp_ac_2 >> 120);
                uint8_t tmp_lane_1000009c8_81_b5_1 = (uint8_t)(tmp_ac_1 >> 120);
                Z0_42 = r2sleigh_bits_insert_256_8(Z0_42, (uint8_t)(tmp_lane_1000009c8_81_b4_1 | tmp_lane_1000009c8_81_b5_1), 120);
                uint32_t tmp_lane_1000009c8_84_b9_1 = r2sleigh_bits_extract_256_32(Z0_1, 0U);
                uint32_t tmp_lane_1000009c8_84_ba_1 = r2sleigh_bits_extract_256_32(Z0_34, 32U);
                uint32_t tmp_lane_1000009c8_85_bb_1 = r2sleigh_bits_extract_256_32(Z0_38, 64U);
                uint32_t tmp_lane_1000009c8_85_bc_1 = r2sleigh_bits_extract_256_32(Z0_42, 96U);
                X11_8 = (uint64_t)(uint32_t)(X11_8 >> 32) << 32 | (uint64_t)(tmp_lane_1000009c8_85_bc_1 + (tmp_lane_1000009c8_84_b9_1 + tmp_lane_1000009c8_84_ba_1 + tmp_lane_1000009c8_85_bb_1));
                X11_8 = (X11_8 & ~((uint64_t)~(uint32_t)0U << 32U)) | (uint64_t)0 << 32;
                X12_4 = X12_1;
            }
        }
        {
            uint64_t X11_13;
            uint64_t X13_2;
            uint32_t tmp_2a000_11 = 0xc2b2ae3d;
            X11_13 = (uint64_t)(uint32_t)((uint32_t)X1_0 + (uint32_t)X11_8);
            uint64_t X13_1 = X12_4 + 4;
            if (X13_1 <= X9_1) {
                uint64_t X12_6;
                uint32_t tmp_2a000_13 = 0x27d4eb2f;
                X12_6 = X12_4;
                for (; ; ) {
                    uint64_t X13_4 = X12_6 + 4;
                    uint64_t tmp_7400_5 = X12_6;
                    X12_6 += 8;
                    uint32_t tmp_24e00_2 = *(uint32_t*)tmp_7400_5;
                    uint32_t tmp_28e80_2 = tmp_24e00_2 * tmp_2a000_11 + (uint32_t)X11_13;
                    X11_13 = (uint64_t)(uint32_t)((tmp_28e80_2 >> 15 | tmp_28e80_2 << 17) * tmp_2a000_13);
                    uint8_t ZR_7 = X12_6 == X9_1;
                    uint8_t CY_7 = X9_1 <= X12_6;
                    uint64_t X12_8 = X13_4;
                    uint8_t tmp_1000_6 = !CY_7 || ZR_7;
                    X12_6 = X12_8;
                    X13_2 = X13_4;
                    if (!tmp_1000_6) {
                        break;
                    }
                }
            } else {
                X13_2 = X12_4;
            }
            {
                uint8_t CY_9 = X9_1 <= X13_2;
                if (!CY_9) {
                    uint64_t X9_3;
                    X9_3 = X0_0 + X1_0 - X13_2;
                    uint32_t tmp_2a000_16 = 0x9e3779b1;
                    for (; ; ) {
                        uint64_t tmp_7400_8 = X13_2;
                        X13_2++;
                        uint8_t tmp_25400_2 = *(uint8_t*)tmp_7400_8;
                        uint32_t tmp_28e80_5 = (uint32_t)tmp_25400_2 * tmp_2a000_2 + (uint32_t)X11_13;
                        X11_13 = (uint64_t)(uint32_t)((tmp_28e80_5 >> 21 | tmp_28e80_5 << 11) * tmp_2a000_16);
                        uint8_t TMPZR_18 = X9_3 == 1;
                        X9_3--;
                        uint8_t tmp_a00_2 = !TMPZR_18;
                        if (!tmp_a00_2) {
                            break;
                        }
                    }
                }
                {
                    uint32_t tmp_lane_100000a70_0_d8_1 = (uint32_t)X11_13;
                    uint32_t tmp_2b380_7 = (tmp_lane_100000a70_0_d8_1 >> 15 ^ tmp_lane_100000a70_0_d8_1) * 0x85ebca77;
                    uint32_t tmp_2b380_8 = tmp_2a000_11 * (tmp_2b380_7 >> 13 ^ tmp_2b380_7);
                    return tmp_2b380_8 >> 16 ^ tmp_2b380_8;
                }
            }
        }
    }
}


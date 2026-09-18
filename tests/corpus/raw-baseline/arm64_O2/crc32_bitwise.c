struct r2sleigh_bits_256 {
    uint8_t bytes[32];
};

uint64_t sym__crc32_bitwise(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 289 source obligations: 277 rendered, 12 elided, 0 refused; 149 statements rendered */
    {
        struct r2sleigh_bits_256 Z2_1;
        Z2_1 = r2sleigh_bits_zero_extend_64_256(0U);
        if (X1_0 == 0) {
            return 0;
        } else {
            uint32_t X10_1;
            uint32_t tmp_20380_8;
            X10_1 = 0xffffffff;
            __uint128_t tmp_lane_1000006b4_7_1_1 = *(__uint128_t*)0x100000fe0;
            __uint128_t tmp_lane_1000006b4_c_4_1 = *(__uint128_t*)0x100000ff0;
            for (; ; ) {
                struct r2sleigh_bits_256 Z2_12;
                struct r2sleigh_bits_256 Z2_16;
                struct r2sleigh_bits_256 Z2_20;
                struct r2sleigh_bits_256 Z2_24;
                struct r2sleigh_bits_256 Z2_48;
                uint8_t* tmp_7400_2 = (uint8_t*)X0_0;
                X0_0++;
                uint8_t tmp_25400_2 = *tmp_7400_2;
                uint32_t tmp_20380_2 = X10_1 ^ (uint32_t)tmp_25400_2;
                uint32_t tmp_20380_3 = tmp_20380_2 >> 1 ^ ((tmp_20380_2 & 1) * 0xffffffff & 0xedb88320);
                uint32_t tmp_20380_4 = tmp_20380_3 >> 1 ^ ((uint32_t)((int32_t)(tmp_20380_2 << 30) >> 31) & 0xedb88320);
                Z2_1 = r2sleigh_bits_insert_256_32(Z2_1, tmp_20380_2, 0);
                Z2_1 = r2sleigh_bits_insert_256_32(Z2_1, tmp_20380_2, 32);
                Z2_1 = r2sleigh_bits_insert_256_32(Z2_1, tmp_20380_2, 64);
                Z2_1 = r2sleigh_bits_insert_256_32(Z2_1, tmp_20380_2, 96);
                Z2_1 = r2sleigh_bits_insert_256_64(Z2_1, 0, 128);
                Z2_1 = r2sleigh_bits_insert_256_64(Z2_1, 0, 192);
                uint8_t tmp_lane_1000006d8_1d_1c_1 = (uint8_t)tmp_lane_1000006b4_7_1_1;
                Z2_1 = r2sleigh_bits_insert_256_8(Z2_1, (uint8_t)((uint8_t)tmp_20380_2 & tmp_lane_1000006d8_1d_1c_1), 0);
                uint8_t tmp_lane_1000006d8_1e_1f_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 8);
                Z2_1 = r2sleigh_bits_insert_256_8(Z2_1, (uint8_t)((uint8_t)(tmp_20380_2 >> 8) & tmp_lane_1000006d8_1e_1f_1), 8);
                uint8_t tmp_lane_1000006d8_1f_22_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 16);
                Z2_1 = r2sleigh_bits_insert_256_8(Z2_1, (uint8_t)((uint8_t)(tmp_20380_2 >> 16) & tmp_lane_1000006d8_1f_22_1), 16);
                uint8_t tmp_lane_1000006d8_20_25_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 24);
                Z2_1 = r2sleigh_bits_insert_256_8(Z2_1, (uint8_t)((uint8_t)(tmp_20380_2 >> 24) & tmp_lane_1000006d8_20_25_1), 24);
                uint8_t tmp_lane_1000006d8_21_28_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 32);
                Z2_12 = r2sleigh_bits_insert_256_8(Z2_1, (uint8_t)((uint8_t)tmp_20380_2 & tmp_lane_1000006d8_21_28_1), 32);
                uint8_t tmp_lane_1000006d8_22_2b_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 40);
                Z2_12 = r2sleigh_bits_insert_256_8(Z2_12, (uint8_t)((uint8_t)(tmp_20380_2 >> 8) & tmp_lane_1000006d8_22_2b_1), 40);
                uint8_t tmp_lane_1000006d8_23_2e_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 48);
                Z2_12 = r2sleigh_bits_insert_256_8(Z2_12, (uint8_t)((uint8_t)(tmp_20380_2 >> 16) & tmp_lane_1000006d8_23_2e_1), 48);
                uint8_t tmp_lane_1000006d8_24_31_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 56);
                Z2_12 = r2sleigh_bits_insert_256_8(Z2_12, (uint8_t)((uint8_t)(tmp_20380_2 >> 24) & tmp_lane_1000006d8_24_31_1), 56);
                uint8_t tmp_lane_1000006d8_25_34_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 64);
                Z2_16 = r2sleigh_bits_insert_256_8(Z2_12, (uint8_t)((uint8_t)tmp_20380_2 & tmp_lane_1000006d8_25_34_1), 64);
                uint8_t tmp_lane_1000006d8_26_37_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 72);
                Z2_16 = r2sleigh_bits_insert_256_8(Z2_16, (uint8_t)((uint8_t)(tmp_20380_2 >> 8) & tmp_lane_1000006d8_26_37_1), 72);
                uint8_t tmp_lane_1000006d8_27_3a_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 80);
                Z2_16 = r2sleigh_bits_insert_256_8(Z2_16, (uint8_t)((uint8_t)(tmp_20380_2 >> 16) & tmp_lane_1000006d8_27_3a_1), 80);
                uint8_t tmp_lane_1000006d8_28_3d_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 88);
                Z2_16 = r2sleigh_bits_insert_256_8(Z2_16, (uint8_t)((uint8_t)(tmp_20380_2 >> 24) & tmp_lane_1000006d8_28_3d_1), 88);
                uint8_t tmp_lane_1000006d8_29_40_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 96);
                Z2_20 = r2sleigh_bits_insert_256_8(Z2_16, (uint8_t)((uint8_t)tmp_20380_2 & tmp_lane_1000006d8_29_40_1), 96);
                uint8_t tmp_lane_1000006d8_2a_43_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 104);
                Z2_20 = r2sleigh_bits_insert_256_8(Z2_20, (uint8_t)((uint8_t)(tmp_20380_2 >> 8) & tmp_lane_1000006d8_2a_43_1), 104);
                uint8_t tmp_lane_1000006d8_2b_46_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 112);
                Z2_20 = r2sleigh_bits_insert_256_8(Z2_20, (uint8_t)((uint8_t)(tmp_20380_2 >> 16) & tmp_lane_1000006d8_2b_46_1), 112);
                uint8_t tmp_lane_1000006d8_2c_49_1 = (uint8_t)(tmp_lane_1000006b4_7_1_1 >> 120);
                Z2_20 = r2sleigh_bits_insert_256_8(Z2_20, (uint8_t)((uint8_t)(tmp_20380_2 >> 24) & tmp_lane_1000006d8_2c_49_1), 120);
                Z2_24 = r2sleigh_bits_insert_256_64(Z2_20, 0, 128);
                Z2_24 = r2sleigh_bits_insert_256_64(Z2_24, 0, 192);
                uint32_t tmp_lane_1000006d8_31_4d_1 = r2sleigh_bits_extract_256_32(Z2_1, 0U);
                uint32_t tmp_lane_1000006d8_33_4e_1 = (uint32_t)(tmp_lane_1000006d8_31_4d_1 == 0) * 0xffffffff;
                Z2_24 = r2sleigh_bits_insert_256_32(Z2_24, tmp_lane_1000006d8_33_4e_1, 0);
                uint32_t tmp_lane_1000006d8_34_4f_1 = r2sleigh_bits_extract_256_32(Z2_12, 32U);
                uint32_t tmp_lane_1000006d8_36_50_1 = (uint32_t)(tmp_lane_1000006d8_34_4f_1 == 0) * 0xffffffff;
                Z2_24 = r2sleigh_bits_insert_256_32(Z2_24, tmp_lane_1000006d8_36_50_1, 32);
                uint32_t tmp_lane_1000006d8_37_51_1 = r2sleigh_bits_extract_256_32(Z2_16, 64U);
                uint32_t tmp_lane_1000006d8_39_52_1 = (uint32_t)(tmp_lane_1000006d8_37_51_1 == 0) * 0xffffffff;
                Z2_24 = r2sleigh_bits_insert_256_32(Z2_24, tmp_lane_1000006d8_39_52_1, 64);
                uint32_t tmp_lane_1000006d8_3a_53_1 = r2sleigh_bits_extract_256_32(Z2_20, 96U);
                uint32_t tmp_lane_1000006d8_3c_54_1 = (uint32_t)(tmp_lane_1000006d8_3a_53_1 == 0) * 0xffffffff;
                Z2_24 = r2sleigh_bits_insert_256_32(Z2_24, tmp_lane_1000006d8_3c_54_1, 96);
                Z2_24 = r2sleigh_bits_insert_256_64(Z2_24, 0, 128);
                Z2_24 = r2sleigh_bits_insert_256_64(Z2_24, 0, 192);
                uint8_t tmp_lane_1000006d8_4f_77_1 = (uint8_t)tmp_lane_1000006b4_c_4_1;
                uint8_t tmp_lane_1000006d8_4f_78_1 = (uint8_t)((uint8_t)~(uint8_t)tmp_lane_1000006d8_33_4e_1 & tmp_lane_1000006d8_4f_77_1);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, tmp_lane_1000006d8_4f_78_1, 0);
                uint8_t tmp_lane_1000006d8_50_79_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 8);
                uint8_t tmp_lane_1000006d8_50_7a_1 = (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_33_4e_1 >> 8) & tmp_lane_1000006d8_50_79_1);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, tmp_lane_1000006d8_50_7a_1, 8);
                uint8_t tmp_lane_1000006d8_51_7b_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 16);
                uint8_t tmp_lane_1000006d8_51_7c_1 = (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_33_4e_1 >> 16) & tmp_lane_1000006d8_51_7b_1);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, tmp_lane_1000006d8_51_7c_1, 16);
                uint8_t tmp_lane_1000006d8_52_7d_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 24);
                uint8_t tmp_lane_1000006d8_52_7e_1 = (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_33_4e_1 >> 24) & tmp_lane_1000006d8_52_7d_1);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, tmp_lane_1000006d8_52_7e_1, 24);
                uint8_t tmp_lane_1000006d8_53_7f_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 32);
                uint8_t tmp_lane_1000006d8_53_80_1 = (uint8_t)((uint8_t)~(uint8_t)tmp_lane_1000006d8_36_50_1 & tmp_lane_1000006d8_53_7f_1);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, tmp_lane_1000006d8_53_80_1, 32);
                uint8_t tmp_lane_1000006d8_54_81_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 40);
                uint8_t tmp_lane_1000006d8_54_82_1 = (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_36_50_1 >> 8) & tmp_lane_1000006d8_54_81_1);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, tmp_lane_1000006d8_54_82_1, 40);
                uint8_t tmp_lane_1000006d8_55_83_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 48);
                uint8_t tmp_lane_1000006d8_55_84_1 = (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_36_50_1 >> 16) & tmp_lane_1000006d8_55_83_1);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, tmp_lane_1000006d8_55_84_1, 48);
                uint8_t tmp_lane_1000006d8_56_85_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 56);
                uint8_t tmp_lane_1000006d8_56_86_1 = (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_36_50_1 >> 24) & tmp_lane_1000006d8_56_85_1);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, tmp_lane_1000006d8_56_86_1, 56);
                uint8_t tmp_lane_1000006d8_57_87_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 64);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, (uint8_t)((uint8_t)~(uint8_t)tmp_lane_1000006d8_39_52_1 & tmp_lane_1000006d8_57_87_1), 64);
                uint8_t tmp_lane_1000006d8_58_89_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 72);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_39_52_1 >> 8) & tmp_lane_1000006d8_58_89_1), 72);
                uint8_t tmp_lane_1000006d8_59_8b_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 80);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_39_52_1 >> 16) & tmp_lane_1000006d8_59_8b_1), 80);
                uint8_t tmp_lane_1000006d8_5a_8d_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 88);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_39_52_1 >> 24) & tmp_lane_1000006d8_5a_8d_1), 88);
                uint8_t tmp_lane_1000006d8_5b_8f_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 96);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, (uint8_t)((uint8_t)~(uint8_t)tmp_lane_1000006d8_3c_54_1 & tmp_lane_1000006d8_5b_8f_1), 96);
                uint8_t tmp_lane_1000006d8_5c_91_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 104);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_3c_54_1 >> 8) & tmp_lane_1000006d8_5c_91_1), 104);
                uint8_t tmp_lane_1000006d8_5d_93_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 112);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_3c_54_1 >> 16) & tmp_lane_1000006d8_5d_93_1), 112);
                uint8_t tmp_lane_1000006d8_5e_95_1 = (uint8_t)(tmp_lane_1000006b4_c_4_1 >> 120);
                Z2_24 = r2sleigh_bits_insert_256_8(Z2_24, (uint8_t)((uint8_t)~(uint8_t)(tmp_lane_1000006d8_3c_54_1 >> 24) & tmp_lane_1000006d8_5e_95_1), 120);
                Z2_48 = r2sleigh_bits_insert_256_64(Z2_24, 0, 128);
                Z2_48 = r2sleigh_bits_insert_256_64(Z2_48, 0, 192);
                __uint128_t tmp_lane_1000006d8_6b_9f_1 = r2sleigh_bits_extract_256_128(Z2_24, 0U);
                __uint128_t tmp_0_2 = tmp_lane_1000006d8_6b_9f_1 >> 64;
                __uint128_t tmp_10_2 = tmp_lane_1000006d8_6b_9f_1 << 64;
                uint64_t Q3_2 = (uint64_t)(tmp_0_2 | tmp_10_2);
                uint8_t tmp_lane_1000006d8_6e_a1_1 = (uint8_t)Q3_2;
                Z2_48 = r2sleigh_bits_insert_256_8(Z2_48, (uint8_t)(tmp_lane_1000006d8_4f_78_1 ^ tmp_lane_1000006d8_6e_a1_1), 0);
                uint8_t tmp_lane_1000006d8_6f_a4_1 = (uint8_t)((__uint128_t)Q3_2 >> 8);
                Z2_48 = r2sleigh_bits_insert_256_8(Z2_48, (uint8_t)(tmp_lane_1000006d8_50_7a_1 ^ tmp_lane_1000006d8_6f_a4_1), 8);
                uint8_t tmp_lane_1000006d8_70_a7_1 = (uint8_t)((__uint128_t)Q3_2 >> 16);
                Z2_48 = r2sleigh_bits_insert_256_8(Z2_48, (uint8_t)(tmp_lane_1000006d8_51_7c_1 ^ tmp_lane_1000006d8_70_a7_1), 16);
                uint8_t tmp_lane_1000006d8_71_aa_1 = (uint8_t)((__uint128_t)Q3_2 >> 24);
                Z2_48 = r2sleigh_bits_insert_256_8(Z2_48, (uint8_t)(tmp_lane_1000006d8_52_7e_1 ^ tmp_lane_1000006d8_71_aa_1), 24);
                uint8_t tmp_lane_1000006d8_72_ad_1 = (uint8_t)((__uint128_t)Q3_2 >> 32);
                Z2_48 = r2sleigh_bits_insert_256_8(Z2_48, (uint8_t)(tmp_lane_1000006d8_53_80_1 ^ tmp_lane_1000006d8_72_ad_1), 32);
                uint8_t tmp_lane_1000006d8_73_b0_1 = (uint8_t)((__uint128_t)Q3_2 >> 40);
                Z2_48 = r2sleigh_bits_insert_256_8(Z2_48, (uint8_t)(tmp_lane_1000006d8_54_82_1 ^ tmp_lane_1000006d8_73_b0_1), 40);
                uint8_t tmp_lane_1000006d8_74_b3_1 = (uint8_t)((__uint128_t)Q3_2 >> 48);
                Z2_48 = r2sleigh_bits_insert_256_8(Z2_48, (uint8_t)(tmp_lane_1000006d8_55_84_1 ^ tmp_lane_1000006d8_74_b3_1), 48);
                uint8_t tmp_lane_1000006d8_75_b6_1 = (uint8_t)((__uint128_t)Q3_2 >> 56);
                Z2_48 = r2sleigh_bits_insert_256_8(Z2_48, (uint8_t)(tmp_lane_1000006d8_56_86_1 ^ tmp_lane_1000006d8_75_b6_1), 56);
                Z2_1 = r2sleigh_bits_insert_256_64(Z2_48, 0, 64);
                Z2_1 = r2sleigh_bits_insert_256_64(Z2_1, 0, 128);
                Z2_1 = r2sleigh_bits_insert_256_64(Z2_1, 0, 192);
                uint64_t tmp_lane_1000006d8_79_bb_1 = r2sleigh_bits_extract_256_64(Z2_48, 0U);
                uint64_t X13_2 = tmp_lane_1000006d8_79_bb_1;
                tmp_20380_8 = (uint32_t)(X13_2 >> 32) ^ ((uint32_t)X13_2 ^ ((uint32_t)((int32_t)(tmp_20380_3 << 26) >> 31) & 0x76dc4190)) ^ (tmp_20380_4 >> 6 ^ ((uint32_t)((int32_t)(tmp_20380_4 << 26) >> 31) & 0xedb88320));
                X10_1 = tmp_20380_8;
                uint8_t TMPZR_2 = X1_0 == 1;
                X1_0--;
                if (TMPZR_2) {
                    break;
                }
            }
            return (uint64_t)~tmp_20380_8;
        }
    }
}


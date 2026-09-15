uint32_t sym__xxhash32(uint64_t X0_0, uint64_t X1_0, uint32_t W2_0)
{
    /* r2dec proof: no individual construct is marked; 260 source obligations: 222 rendered, 38 elided, 0 refused; 161 statements rendered */
    {
        uint64_t X2_0_2;
        uint64_t X14_8;
        uint64_t X12_8;
        X2_0_2 = (uint64_t)(uint32_t)W2_0;
        uint32_t tmp_2a000_2 = 0x9e3779b1;
        uint32_t tmp_2a000_4 = 0x85ebca77;
        uint32_t tmp_2a000_6 = 0x165667b1;
        uint64_t tmp_12380_1 = X1_0;
        uint64_t tmp_12480_1 = X0_0 + tmp_12380_1;
        uint64_t X11_1 = tmp_12480_1;
        uint8_t CY_1 = 16 <= X1_0;
        if (!CY_1) {
            uint32_t tmp_12180_7 = tmp_2a000_6;
            uint32_t tmp_lane_1000008f8_1_2e_1 = W2_0;
            uint32_t tmp_12280_7 = tmp_lane_1000008f8_1_2e_1 + tmp_12180_7;
            X14_8 = (uint64_t)(uint32_t)tmp_12280_7;
            X12_8 = X0_0;
        } else {
            uint64_t X15_1;
            uint64_t X16_1;
            uint64_t X14_1;
            uint64_t X12_5;
            uint32_t tmp_2b380_5;
            uint32_t tmp_2b380_2;
            uint32_t tmp_2b380_3;
            uint32_t tmp_2b380_4;
            uint64_t X13_1 = X11_1 - 16;
            uint32_t tmp_2a000_8 = 0x24234428;
            uint32_t tmp_12180_1 = tmp_2a000_8;
            uint32_t tmp_lane_100000870_6_5_1 = W2_0;
            uint32_t tmp_12280_1 = tmp_lane_100000870_6_5_1 + tmp_12180_1;
            X15_1 = (uint64_t)(uint32_t)tmp_12280_1;
            uint32_t tmp_12180_2 = tmp_2a000_4;
            uint32_t tmp_lane_100000870_d_7_1 = W2_0;
            uint32_t tmp_12280_2 = tmp_lane_100000870_d_7_1 + tmp_12180_2;
            X16_1 = (uint64_t)(uint32_t)tmp_12280_2;
            uint32_t tmp_2a000_10 = 0x61c8864f;
            uint32_t tmp_12180_3 = tmp_2a000_10;
            uint32_t tmp_lane_100000870_18_a_1 = W2_0;
            uint32_t tmp_12280_3 = tmp_lane_100000870_18_a_1 + tmp_12180_3;
            X14_1 = (uint64_t)(uint32_t)tmp_12280_3;
            X12_5 = X0_0;
            for (; ; ) {
                uint64_t tmp_7c00_2 = X12_5;
                uint32_t tmp_24280_2 = *(uint32_t*)tmp_7c00_2;
                uint32_t tmp_24480_2 = ((uint32_t*)tmp_7c00_2)[1];
                uint32_t tmp_28d80_2 = tmp_24280_2 * tmp_2a000_4;
                uint32_t tmp_lane_100000894_9_d_1 = (uint32_t)X15_1;
                uint32_t tmp_28e80_2 = tmp_lane_100000894_9_d_1 + tmp_28d80_2;
                uint32_t tmp_28d80_3 = tmp_24480_2 * tmp_2a000_4;
                uint32_t tmp_lane_100000894_e_10_1 = (uint32_t)X16_1;
                uint32_t tmp_28e80_3 = tmp_lane_100000894_e_10_1 + tmp_28d80_3;
                uint32_t* tmp_7b80_2 = (uint32_t*)(X12_5 + 8);
                uint32_t tmp_24280_3 = *tmp_7b80_2;
                uint32_t tmp_24480_3 = tmp_7b80_2[1];
                uint64_t X3_3 = (uint64_t)tmp_24480_3;
                uint32_t tmp_28d80_4 = tmp_24280_3 * tmp_2a000_4;
                uint32_t tmp_lane_100000894_1b_13_1 = (uint32_t)X2_0_2;
                uint32_t tmp_28e80_4 = tmp_lane_100000894_1b_13_1 + tmp_28d80_4;
                uint32_t tmp_31880_2 = tmp_28e80_2 >> 19 | tmp_28e80_2 << 13;
                tmp_2b380_2 = tmp_31880_2 * tmp_2a000_2;
                X15_1 = (uint64_t)(uint32_t)tmp_2b380_2;
                uint32_t tmp_31880_3 = tmp_28e80_3 >> 19 | tmp_28e80_3 << 13;
                tmp_2b380_3 = tmp_31880_3 * tmp_2a000_2;
                X16_1 = (uint64_t)(uint32_t)tmp_2b380_3;
                uint32_t tmp_31880_4 = tmp_28e80_4 >> 19 | tmp_28e80_4 << 13;
                tmp_2b380_4 = tmp_31880_4 * tmp_2a000_2;
                X2_0_2 = (uint64_t)(uint32_t)tmp_2b380_4;
                uint32_t tmp_28d80_5 = (uint32_t)X3_3 * tmp_2a000_4;
                uint32_t tmp_lane_100000894_35_1f_1 = (uint32_t)X14_1;
                uint32_t tmp_28e80_5 = tmp_lane_100000894_35_1f_1 + tmp_28d80_5;
                uint32_t tmp_31880_5 = tmp_28e80_5 >> 19 | tmp_28e80_5 << 13;
                tmp_2b380_5 = tmp_31880_5 * tmp_2a000_2;
                X14_1 = (uint64_t)(uint32_t)tmp_2b380_5;
                X12_5 += 16;
                uint8_t TMPCY_12 = X13_1 <= X12_5;
                uint8_t TMPZR_8 = X12_5 == X13_1;
                uint8_t ZR_3 = TMPZR_8;
                uint8_t CY_3 = TMPCY_12;
                if (!(!CY_3 || ZR_3)) {
                    break;
                }
            }
            {
                uint32_t tmp_12280_4;
                uint32_t tmp_31880_6 = tmp_2b380_2 >> 31 | tmp_2b380_2 << 1;
                uint32_t tmp_31880_7 = tmp_2b380_3 >> 25 | tmp_2b380_3 << 7;
                uint32_t tmp_12180_4 = tmp_31880_6;
                tmp_12280_4 = tmp_31880_7 + tmp_12180_4;
                uint32_t tmp_31880_8 = tmp_2b380_4 >> 20 | tmp_2b380_4 << 12;
                uint32_t tmp_31880_9 = tmp_2b380_5 >> 14 | tmp_2b380_5 << 18;
                uint32_t tmp_12180_5 = tmp_31880_9;
                uint32_t tmp_12280_5 = tmp_31880_8 + tmp_12180_5;
                uint32_t tmp_12180_6 = tmp_12280_5;
                tmp_12280_4 += tmp_12180_6;
                X14_8 = (uint64_t)(uint32_t)tmp_12280_4;
                X12_8 = X12_5;
            }
        }
        {
            uint64_t X14_11;
            uint64_t X15_10;
            uint32_t tmp_2a000_13 = 0xc2b2ae3d;
            uint32_t tmp_12180_9 = (uint32_t)X1_0;
            uint32_t tmp_lane_100000900_5_31_1 = (uint32_t)X14_8;
            uint32_t tmp_12280_9 = tmp_lane_100000900_5_31_1 + tmp_12180_9;
            X14_11 = (uint64_t)(uint32_t)tmp_12280_9;
            uint64_t tmp_11f80_4 = X12_8 + 4;
            uint64_t X15_9 = tmp_11f80_4;
            uint8_t TMPCY_20 = X11_1 <= X15_9;
            uint8_t TMPZR_16 = X15_9 == X11_1;
            uint8_t ZR_5 = TMPZR_16;
            uint8_t CY_5 = TMPCY_20;
            if (!CY_5 || ZR_5) {
                uint64_t X12_10;
                uint32_t tmp_2a000_15 = 0x27d4eb2f;
                X12_10 = X12_8;
                for (; ; ) {
                    uint64_t tmp_11f80_6 = X12_10 + 4;
                    uint64_t X15_12 = tmp_11f80_6;
                    uint64_t tmp_7400_2 = X12_10;
                    X12_10 += 8;
                    uint32_t tmp_24e00_2 = *(uint32_t*)tmp_7400_2;
                    uint32_t tmp_28d80_8 = tmp_24e00_2 * tmp_2a000_13;
                    uint32_t tmp_lane_100000928_c_35_1 = (uint32_t)X14_11;
                    uint32_t tmp_28e80_8 = tmp_lane_100000928_c_35_1 + tmp_28d80_8;
                    uint32_t tmp_31880_12 = tmp_28e80_8 >> 15 | tmp_28e80_8 << 17;
                    X14_11 = (uint64_t)(uint32_t)(tmp_31880_12 * tmp_2a000_15);
                    uint8_t TMPCY_24 = X11_1 <= X12_10;
                    uint8_t TMPZR_19 = X12_10 == X11_1;
                    uint8_t ZR_7 = TMPZR_19;
                    uint8_t CY_7 = TMPCY_24;
                    uint64_t X12_12 = X15_12;
                    X12_10 = X12_12;
                    X15_10 = X15_12;
                    if (!(!CY_7 || ZR_7)) {
                        break;
                    }
                }
            } else {
                X15_10 = X12_8;
            }
            {
                uint8_t TMPCY_26 = X11_1 <= X15_10;
                uint8_t CY_9 = TMPCY_26;
                if (!CY_9) {
                    uint64_t X11_3;
                    uint64_t tmp_12380_2 = X0_0;
                    uint64_t tmp_12480_2 = X1_0 + tmp_12380_2;
                    X11_3 = tmp_12480_2 - X15_10;
                    for (; ; ) {
                        uint64_t tmp_7400_5 = X15_10;
                        X15_10++;
                        uint8_t tmp_25400_2 = *(uint8_t*)tmp_7400_5;
                        uint32_t tmp_28d80_11 = (uint32_t)tmp_25400_2 * tmp_2a000_6;
                        uint32_t tmp_lane_100000958_5_3b_1 = (uint32_t)X14_11;
                        uint32_t tmp_28e80_11 = tmp_lane_100000958_5_3b_1 + tmp_28d80_11;
                        uint32_t tmp_31880_15 = tmp_28e80_11 >> 21 | tmp_28e80_11 << 11;
                        X14_11 = (uint64_t)(uint32_t)(tmp_31880_15 * tmp_2a000_2);
                        uint64_t tmp_3e280_2 = X11_3 - 1;
                        uint8_t TMPZR_24 = X11_3 == 1;
                        uint64_t X11_5 = tmp_3e280_2;
                        uint8_t ZR_11 = TMPZR_24;
                        X11_3 = X11_5;
                        if (ZR_11) {
                            break;
                        }
                    }
                }
                {
                    uint32_t tmp_lane_100000970_0_3f_1 = (uint32_t)X14_11;
                    uint32_t tmp_20380_1 = tmp_lane_100000970_0_3f_1 >> 15 ^ tmp_lane_100000970_0_3f_1;
                    uint32_t tmp_2b380_13 = tmp_20380_1 * tmp_2a000_4;
                    uint32_t tmp_20380_2 = tmp_2b380_13 >> 13 ^ tmp_2b380_13;
                    uint32_t tmp_2b380_14 = tmp_20380_2 * tmp_2a000_13;
                    uint32_t tmp_20380_3 = tmp_2b380_14 >> 16 ^ tmp_2b380_14;
                    return tmp_20380_3;
                }
            }
        }
    }
}


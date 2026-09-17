uint32_t sym__xxhash32(uint64_t X0_0, uint64_t X1_0, uint32_t W2_0)
{
    /* r2dec proof: no individual construct is marked; 245 source obligations: 207 rendered, 38 elided, 0 refused; 83 statements rendered */
    {
        uint64_t X2_0_2;
        uint64_t X12_5;
        uint64_t X14_8;
        X2_0_2 = (uint64_t)(uint32_t)W2_0;
        uint32_t tmp_2a000_2 = 0x9e3779b1;
        uint32_t tmp_2a000_4 = 0x85ebca77;
        uint32_t tmp_2a000_6 = 0x165667b1;
        uint64_t X11_1 = X1_0 + X0_0;
        if (X1_0 < 16) {
            X14_8 = (uint64_t)(uint32_t)(tmp_2a000_6 + W2_0);
            X12_5 = X0_0;
        } else {
            uint64_t X15_1;
            uint64_t X16_1;
            uint64_t X14_1;
            uint32_t tmp_2b380_5;
            uint32_t tmp_2b380_2;
            uint32_t tmp_2b380_3;
            uint32_t tmp_2b380_4;
            uint64_t X13_1 = X11_1 - 16;
            X15_1 = (uint64_t)(uint32_t)(W2_0 + 0x24234428);
            X16_1 = (uint64_t)(uint32_t)(W2_0 + tmp_2a000_4);
            X14_1 = (uint64_t)(uint32_t)(W2_0 + 0x61c8864f);
            X12_5 = X0_0;
            for (; ; ) {
                uint64_t tmp_7c00_2 = X12_5;
                uint32_t tmp_24280_2 = *(uint32_t*)tmp_7c00_2;
                uint32_t tmp_24480_2 = ((uint32_t*)tmp_7c00_2)[1];
                uint32_t tmp_28e80_2 = (uint32_t)X15_1 + tmp_24280_2 * tmp_2a000_4;
                uint32_t tmp_28e80_3 = (uint32_t)X16_1 + tmp_24480_2 * tmp_2a000_4;
                uint32_t* tmp_7b80_2 = (uint32_t*)(X12_5 + 8);
                uint32_t tmp_24280_3 = *tmp_7b80_2;
                uint32_t tmp_24480_3 = tmp_7b80_2[1];
                uint32_t tmp_28e80_4 = (uint32_t)X2_0_2 + tmp_24280_3 * tmp_2a000_4;
                tmp_2b380_2 = (tmp_28e80_2 >> 19 | tmp_28e80_2 << 13) * tmp_2a000_2;
                X15_1 = (uint64_t)(uint32_t)tmp_2b380_2;
                tmp_2b380_3 = (tmp_28e80_3 >> 19 | tmp_28e80_3 << 13) * tmp_2a000_2;
                X16_1 = (uint64_t)(uint32_t)tmp_2b380_3;
                tmp_2b380_4 = (tmp_28e80_4 >> 19 | tmp_28e80_4 << 13) * tmp_2a000_2;
                X2_0_2 = (uint64_t)(uint32_t)tmp_2b380_4;
                uint32_t tmp_28e80_5 = (uint32_t)X14_1 + tmp_24480_3 * tmp_2a000_4;
                tmp_2b380_5 = (tmp_28e80_5 >> 19 | tmp_28e80_5 << 13) * tmp_2a000_2;
                X14_1 = (uint64_t)(uint32_t)tmp_2b380_5;
                X12_5 += 16;
                if (X13_1 < X12_5) {
                    break;
                }
            }
            X14_8 = (uint64_t)(uint32_t)((tmp_2b380_5 >> 14 | tmp_2b380_5 << 18) + ((tmp_2b380_2 >> 31 | tmp_2b380_2 << 1) + (tmp_2b380_3 >> 25 | tmp_2b380_3 << 7) + (tmp_2b380_4 >> 20 | tmp_2b380_4 << 12)));
        }
        {
            uint64_t X14_11;
            uint64_t X15_10;
            uint32_t tmp_2a000_13 = 0xc2b2ae3d;
            X14_11 = (uint64_t)(uint32_t)((uint32_t)X1_0 + (uint32_t)X14_8);
            uint64_t X15_9 = X12_5 + 4;
            if (X15_9 <= X11_1) {
                uint32_t tmp_2a000_15 = 0x27d4eb2f;
                for (; ; ) {
                    X15_10 = X12_5 + 4;
                    uint64_t tmp_7400_2 = X12_5;
                    X12_5 += 8;
                    uint32_t tmp_24e00_2 = *(uint32_t*)tmp_7400_2;
                    uint32_t tmp_28e80_8 = tmp_24e00_2 * tmp_2a000_13 + (uint32_t)X14_11;
                    X14_11 = (uint64_t)(uint32_t)((tmp_28e80_8 >> 15 | tmp_28e80_8 << 17) * tmp_2a000_15);
                    uint8_t ZR_7 = X12_5 == X11_1;
                    uint8_t CY_7 = X11_1 <= X12_5;
                    X12_5 = X15_10;
                    if (!(!CY_7 || ZR_7)) {
                        break;
                    }
                }
            } else {
                X15_10 = X12_5;
            }
            {
                if (X15_10 < X11_1) {
                    uint64_t X11_3;
                    X11_3 = X0_0 + X1_0 - X15_10;
                    for (; ; ) {
                        uint64_t tmp_7400_5 = X15_10;
                        X15_10++;
                        uint8_t tmp_25400_2 = *(uint8_t*)tmp_7400_5;
                        uint32_t tmp_28e80_11 = (uint32_t)tmp_25400_2 * tmp_2a000_6 + (uint32_t)X14_11;
                        X14_11 = (uint64_t)(uint32_t)((tmp_28e80_11 >> 21 | tmp_28e80_11 << 11) * tmp_2a000_2);
                        uint8_t TMPZR_24 = X11_3 == 1;
                        X11_3--;
                        if (TMPZR_24) {
                            break;
                        }
                    }
                }
                {
                    uint32_t tmp_lane_100000970_0_3f_1 = (uint32_t)X14_11;
                    uint32_t tmp_2b380_13 = tmp_2a000_4 * (tmp_lane_100000970_0_3f_1 >> 15 ^ tmp_lane_100000970_0_3f_1);
                    uint32_t tmp_2b380_14 = tmp_2a000_13 * (tmp_2b380_13 >> 13 ^ tmp_2b380_13);
                    return tmp_2b380_14 >> 16 ^ tmp_2b380_14;
                }
            }
        }
    }
}


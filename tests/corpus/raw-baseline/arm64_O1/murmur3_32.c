uint32_t sym__murmur3_32(uint64_t X0_0, uint64_t X1_0, uint32_t W2_0)
{
    /* r2dec proof: no individual construct is marked; 137 source obligations: 122 rendered, 15 elided, 0 refused; 73 statements rendered */
    {
        uint64_t X2_0_2;
        X2_0_2 = (uint64_t)(uint32_t)W2_0;
        uint32_t tmp_2a000_2 = 0xcc9e2d51;
        uint32_t tmp_2a000_4 = 0x1b873593;
        uint8_t tmp_b00_1 = X1_0 < 4;
        if (!tmp_b00_1) {
            uint64_t X10_1;
            uint8_t* X12_1;
            X10_1 = X1_0 >> 2;
            uint32_t tmp_2a000_6 = 0xe6546b64;
            X12_1 = (uint8_t*)X0_0;
            for (; ; ) {
                uint8_t* tmp_7400_2 = X12_1;
                X12_1 = (uint8_t*)((uint64_t)X12_1 + 4);
                uint32_t tmp_24e00_2 = (uint32_t)*(int32_t*)tmp_7400_2;
                uint32_t tmp_2b380_2 = tmp_24e00_2 * tmp_2a000_2;
                uint32_t tmp_20380_2 = (tmp_2b380_2 >> 17 | tmp_2b380_2 << 15) * tmp_2a000_4 ^ (uint32_t)X2_0_2;
                uint32_t tmp_31880_3 = tmp_20380_2 >> 19 | tmp_20380_2 << 13;
                uint32_t tmp_12280_2 = tmp_31880_3 + tmp_31880_3 * 4;
                X2_0_2 = (uint64_t)(uint32_t)(tmp_2a000_6 + tmp_12280_2);
                uint64_t tmp_3e280_2 = X10_1 - 1;
                uint8_t TMPZR_5 = X10_1 == 1;
                uint64_t X10_3 = tmp_3e280_2;
                uint8_t tmp_a00_2 = !TMPZR_5;
                X10_1 = X10_3;
                if (!tmp_a00_2) {
                    break;
                }
            }
        }
        {
            uint64_t X2_4;
            uint8_t* X11_5 = (uint8_t*)((X1_0 & (uint64_t)-0x4) + X0_0);
            uint64_t X12_5 = X1_0 & 3;
            uint8_t TMPOV_8 = r2sleigh_int_sborrow_64(X12_5, 1);
            uint8_t TMPNG_8 = (int64_t)(X12_5 - 1) < 0;
            uint8_t TMPZR_8 = X12_5 == 1;
            uint8_t NG_5 = TMPNG_8;
            uint8_t ZR_5 = TMPZR_8;
            uint8_t OV_5 = TMPOV_8;
            {
                uint64_t X10_9;
                uint8_t tmp_25500_5;
                uint32_t tmp_20380_4;
                uint32_t tmp_2b380_5;
                uint32_t tmp_31880_5;
                uint32_t tmp_2b380_6;
                if (!ZR_5 && NG_5 == OV_5) {
                    uint64_t X10_7;
                    uint8_t TMPZR_9 = X12_5 == 2;
                    uint8_t ZR_6 = TMPZR_9;
                    X10_7 = 0;
                    if (!ZR_6) {
                        uint8_t tmp_25500_1 = *(uint8_t*)((uint64_t)X11_5 + 2);
                        X10_7 = (uint64_t)(uint32_t)((uint32_t)tmp_25500_1 << 16);
                    }
                    {
                        uint8_t tmp_25500_3 = *(uint8_t*)((uint64_t)X11_5 + 1);
                        uint64_t X12_6 = (uint64_t)(uint8_t)tmp_25500_3;
                        X10_9 = (uint64_t)(uint32_t)((uint32_t)X12_6 << 8 | (uint32_t)X10_7);
                        {
                            tmp_25500_5 = *X11_5;
                            tmp_20380_4 = (uint32_t)X10_9 ^ (uint32_t)tmp_25500_5;
                            tmp_2b380_5 = tmp_20380_4 * tmp_2a000_2;
                            tmp_31880_5 = tmp_2b380_5 >> 17 | tmp_2b380_5 << 15;
                            tmp_2b380_6 = tmp_31880_5 * tmp_2a000_4;
                            X2_4 = (uint64_t)(uint32_t)((uint32_t)X2_0_2 ^ tmp_2b380_6);
                        }
                    }
                } else {
                    X10_9 = 0;
                    if (X12_5 != 0) {
                        tmp_25500_5 = *X11_5;
                        tmp_20380_4 = (uint32_t)X10_9 ^ (uint32_t)tmp_25500_5;
                        tmp_2b380_5 = tmp_20380_4 * tmp_2a000_2;
                        tmp_31880_5 = tmp_2b380_5 >> 17 | tmp_2b380_5 << 15;
                        tmp_2b380_6 = tmp_31880_5 * tmp_2a000_4;
                        X2_4 = (uint64_t)(uint32_t)((uint32_t)X2_0_2 ^ tmp_2b380_6);
                    } else {
                        X2_4 = X2_0_2;
                    }
                }
            }
            {
                uint32_t tmp_20380_7 = (uint32_t)X2_4 ^ (uint32_t)X1_0;
                uint32_t tmp_2b380_8 = (tmp_20380_7 >> 16 ^ tmp_20380_7) * 0x85ebca6b;
                uint32_t tmp_2b380_9 = (tmp_2b380_8 >> 13 ^ tmp_2b380_8) * 0xc2b2ae35;
                uint32_t tmp_20380_10 = tmp_2b380_9 >> 16 ^ tmp_2b380_9;
                return tmp_20380_10;
            }
        }
    }
}


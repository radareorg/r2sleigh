uint64_t sym__unaligned_words(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 95 source obligations: 77 rendered, 18 elided, 0 refused; 58 statements rendered */
    {
        uint64_t X0_2;
        uint64_t X11_1;
        uint8_t* X8_1 = (uint8_t*)X0_0;
        X0_2 = (uint64_t)0x9e3779b9;
        uint32_t tmp_2a000_4 = 0x1000193;
        uint8_t TMPCY_1 = 8 <= X1_0;
        uint8_t CY_1 = TMPCY_1;
        if (CY_1) {
            uint64_t X12_1;
            X12_1 = 0;
            uint64_t tmp_11f80_1 = (uint64_t)X8_1 + 1;
            uint64_t X10_1 = tmp_11f80_1;
            for (; ; ) {
                uint32_t tmp_25180_2 = *(uint32_t*)(X12_1 + X10_1);
                uint32_t tmp_20380_2 = (uint32_t)X0_2 ^ tmp_25180_2;
                X0_2 = (uint64_t)(uint32_t)(tmp_20380_2 * tmp_2a000_4);
                uint64_t tmp_11f80_3 = X12_1 + 7;
                uint64_t X11_5 = tmp_11f80_3;
                uint64_t tmp_11f80_4 = X12_1 + 15;
                uint64_t X13_2 = tmp_11f80_4;
                uint64_t X12_3 = X11_5;
                uint8_t TMPCY_6 = X1_0 <= X13_2;
                uint8_t TMPZR_6 = X13_2 == X1_0;
                uint8_t ZR_3 = TMPZR_6;
                uint8_t CY_3 = TMPCY_6;
                X12_1 = X12_3;
                X11_1 = X11_5;
                if (!(!CY_3 || ZR_3)) {
                    break;
                }
            }
        } else {
            X11_1 = 0;
        }
        {
            uint64_t X10_4;
            uint64_t tmp_3e680_1 = X11_1;
            uint8_t TMPCY_8 = tmp_3e680_1 <= X1_0;
            uint64_t tmp_3e780_1 = X1_0 - tmp_3e680_1;
            uint8_t TMPZR_8 = X1_0 == tmp_3e680_1;
            uint64_t X10_3 = tmp_3e780_1;
            uint8_t ZR_5 = TMPZR_8;
            uint8_t CY_5 = TMPCY_8;
            X10_4 = X10_3;
            if (!(!CY_5 || ZR_5)) {
                uint8_t* X8_2;
                uint64_t tmp_12380_1 = X11_1;
                uint8_t* tmp_12480_1 = (uint8_t*)((uint64_t)X8_1 + tmp_12380_1);
                X8_2 = tmp_12480_1;
                for (; ; ) {
                    uint8_t* tmp_7400_2 = X8_2;
                    X8_2 = (uint8_t*)((uint64_t)X8_2 + 1);
                    uint8_t tmp_25400_2 = *tmp_7400_2;
                    uint32_t tmp_20380_5 = (uint32_t)X0_2 ^ (uint32_t)tmp_25400_2;
                    X0_2 = (uint64_t)(uint32_t)(tmp_20380_5 * tmp_2a000_4);
                    uint64_t tmp_3e280_2 = X10_4 - 1;
                    uint8_t TMPZR_11 = X10_4 == 1;
                    uint64_t X10_5 = tmp_3e280_2;
                    uint8_t ZR_7 = TMPZR_11;
                    X10_4 = X10_5;
                    if (ZR_7) {
                        break;
                    }
                }
            }
            return X0_2;
        }
    }
}


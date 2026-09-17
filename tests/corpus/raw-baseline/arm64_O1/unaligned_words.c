uint64_t sym__unaligned_words(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 92 source obligations: 73 rendered, 19 elided, 0 refused; 34 statements rendered */
    {
        uint64_t X0_2;
        uint64_t X11_1;
        uint8_t* X8_1 = (uint8_t*)X0_0;
        X0_2 = (uint64_t)0x9e3779b9;
        uint32_t tmp_2a000_4 = 0x1000193;
        if (8 <= X1_0) {
            uint64_t X12_1;
            X12_1 = 0;
            uint64_t X10_1 = (uint64_t)X8_1 + 1;
            for (; ; ) {
                uint32_t tmp_25180_2 = *(uint32_t*)(X12_1 + X10_1);
                X0_2 = (uint64_t)(uint32_t)(tmp_2a000_4 * ((uint32_t)X0_2 ^ tmp_25180_2));
                X11_1 = X12_1 + 7;
                uint64_t X13_2 = X12_1 + 15;
                X12_1 = X11_1;
                if (X1_0 < X13_2) {
                    break;
                }
            }
        } else {
            X11_1 = 0;
        }
        {
            uint64_t X10_3;
            X10_3 = X1_0 - X11_1;
            if (X11_1 < X1_0) {
                uint8_t* X8_2;
                X8_2 = (uint8_t*)(X11_1 + (uint64_t)X8_1);
                for (; ; ) {
                    uint8_t* tmp_7400_2 = X8_2;
                    X8_2 = (uint8_t*)((uint64_t)X8_2 + 1);
                    uint8_t tmp_25400_2 = *tmp_7400_2;
                    X0_2 = (uint64_t)(uint32_t)(((uint32_t)X0_2 ^ (uint32_t)tmp_25400_2) * tmp_2a000_4);
                    uint8_t TMPZR_11 = X10_3 == 1;
                    X10_3--;
                    uint8_t tmp_a00_2 = !TMPZR_11;
                    if (!tmp_a00_2) {
                        break;
                    }
                }
            }
            return X0_2;
        }
    }
}


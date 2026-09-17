uint64_t sym__sdbm(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 39 source obligations: 30 rendered, 9 elided, 0 refused; 18 statements rendered */
    if (X1_0 == 0) {
        return 0;
    } else {
        uint8_t* X8_1;
        uint64_t X0_1;
        X8_1 = (uint8_t*)X0_0;
        X0_1 = 0;
        uint32_t tmp_2a000_2 = 0x1003f;
        for (; ; ) {
            uint8_t* tmp_7400_2 = X8_1;
            X8_1 = (uint8_t*)((uint64_t)X8_1 + 1);
            uint8_t tmp_25400_2 = *tmp_7400_2;
            X0_1 = (uint64_t)(uint32_t)((uint32_t)X0_1 * tmp_2a000_2 + (uint32_t)tmp_25400_2);
            uint8_t TMPZR_2 = X1_0 == 1;
            X1_0--;
            uint8_t tmp_a00_2 = !TMPZR_2;
            if (!tmp_a00_2) {
                break;
            }
        }
        return X0_1;
    }
}


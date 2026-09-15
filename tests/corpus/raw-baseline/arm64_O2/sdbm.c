uint64_t sym__sdbm(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 41 source obligations: 30 rendered, 11 elided, 0 refused; 25 statements rendered */
    if (X1_0 == 0) {
        uint64_t X0_4 = 0;
        return X0_4;
    } else {
        uint8_t* X8_1;
        uint64_t X0_1;
        uint64_t X1_2;
        X8_1 = (uint8_t*)X0_0;
        X0_1 = 0;
        uint32_t tmp_2a000_2 = 0x1003f;
        X1_2 = X1_0;
        for (; ; ) {
            uint8_t* tmp_7400_2 = X8_1;
            X8_1 = (uint8_t*)((uint64_t)X8_1 + 1);
            uint8_t tmp_25400_2 = *tmp_7400_2;
            uint64_t X10_2 = (uint64_t)(uint8_t)tmp_25400_2;
            uint32_t tmp_28d80_2 = (uint32_t)X0_1 * tmp_2a000_2;
            uint32_t tmp_lane_1000005e8_5_3_1 = (uint32_t)X10_2;
            X0_1 = (uint64_t)(uint32_t)(tmp_lane_1000005e8_5_3_1 + tmp_28d80_2);
            uint64_t tmp_3e280_2 = X1_2 - 1;
            uint8_t TMPZR_2 = X1_2 == 1;
            X1_2 = tmp_3e280_2;
            uint8_t ZR_2 = TMPZR_2;
            if (ZR_2) {
                break;
            }
        }
        return X0_1;
    }
}


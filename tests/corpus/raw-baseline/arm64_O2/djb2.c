uint64_t sym__djb2(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 39 source obligations: 29 rendered, 10 elided, 0 refused; 21 statements rendered */
    {
        uint64_t X8_1;
        uint64_t X1_1;
        X8_1 = 0x1505;
        X1_1 = X1_0;
        if (X1_0 != 0) {
            for (; ; ) {
                uint32_t tmp_lane_1000005b8_0_0_1 = (uint32_t)X8_1;
                uint32_t tmp_12280_2 = tmp_lane_1000005b8_0_0_1 + tmp_lane_1000005b8_0_0_1 * 32;
                uint8_t* tmp_7400_2 = (uint8_t*)X0_0;
                X0_0++;
                uint8_t tmp_25400_2 = *tmp_7400_2;
                X8_1 = (uint64_t)(uint32_t)((uint32_t)tmp_25400_2 + tmp_12280_2);
                uint64_t tmp_3e280_2 = X1_1 - 1;
                uint8_t TMPZR_4 = X1_1 == 1;
                uint64_t X1_2 = tmp_3e280_2;
                uint8_t tmp_a00_2 = !TMPZR_4;
                X1_1 = X1_2;
                if (!tmp_a00_2) {
                    break;
                }
            }
        }
        {
            uint64_t X0_4 = X8_1;
            return X0_4;
        }
    }
}


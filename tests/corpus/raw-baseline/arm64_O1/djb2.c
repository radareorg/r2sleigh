uint64_t sym__djb2(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 37 source obligations: 26 rendered, 11 elided, 0 refused; 13 statements rendered */
    {
        uint64_t X8_1;
        X8_1 = 0x1505;
        if (X1_0 != 0) {
            for (; ; ) {
                uint32_t tmp_lane_1000005b8_0_0_1 = (uint32_t)X8_1;
                uint8_t* tmp_7400_2 = (uint8_t*)X0_0;
                X0_0++;
                uint8_t tmp_25400_2 = *tmp_7400_2;
                X8_1 = (uint64_t)((uint32_t)tmp_25400_2 + (tmp_lane_1000005b8_0_0_1 * 32 + tmp_lane_1000005b8_0_0_1));
                X1_0--;
                if (X1_0 == 0) {
                    break;
                }
            }
        }
        return X8_1;
    }
}


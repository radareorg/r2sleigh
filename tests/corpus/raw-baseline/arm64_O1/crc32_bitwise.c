uint64_t sym__crc32_bitwise(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 66 source obligations: 52 rendered, 14 elided, 0 refused; 30 statements rendered */
    if (X1_0 == 0) {
        return 0;
    } else {
        uint64_t X9_1;
        uint64_t X8_1;
        uint32_t tmp_20380_4;
        X9_1 = 0;
        X8_1 = 0xffffffff;
        uint32_t tmp_2a000_2 = 0xedb88320;
        for (; ; ) {
            uint64_t X11_5;
            uint8_t tmp_25600_2 = ((uint8_t*)X0_0)[X9_1];
            X8_1 = (uint64_t)(uint32_t)((uint32_t)X8_1 ^ (uint32_t)tmp_25600_2);
            X11_5 = 8;
            for (; ; ) {
                uint32_t tmp_12880_3 = ((uint32_t)X8_1 & 1) * 0xffffffff & tmp_2a000_2;
                tmp_20380_4 = (uint32_t)X8_1 >> 1 ^ tmp_12880_3;
                X8_1 = (uint64_t)(uint32_t)tmp_20380_4;
                uint32_t tmp_lane_1000006d0_a_8_1 = (uint32_t)X11_5;
                uint32_t tmp_3de80_3 = tmp_lane_1000006d0_a_8_1 - 1;
                X11_5 = (uint64_t)(uint32_t)tmp_3de80_3;
                uint8_t tmp_a00_3 = tmp_lane_1000006d0_a_8_1 != 1;
                if (!tmp_a00_3) {
                    break;
                }
            }
            {
                X9_1++;
                uint8_t TMPZR_5 = X9_1 == X1_0;
                uint8_t ZR_4 = TMPZR_5;
                uint8_t tmp_a00_4 = !ZR_4;
                if (!tmp_a00_4) {
                    break;
                }
            }
        }
        return (uint64_t)~tmp_20380_4;
    }
}


uint64_t sym__crc32_bitwise(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 63 source obligations: 51 rendered, 12 elided, 0 refused; 23 statements rendered */
    if (X1_0 == 0) {
        return 0;
    } else {
        uint64_t X9_1;
        uint32_t X8_1;
        uint32_t tmp_20380_4;
        X9_1 = 0;
        X8_1 = 0xffffffff;
        for (; ; ) {
            uint32_t X11_5;
            uint8_t tmp_25600_2 = ((uint8_t*)X0_0)[X9_1];
            X8_1 ^= (uint32_t)tmp_25600_2;
            X11_5 = 8;
            for (; ; ) {
                tmp_20380_4 = X8_1 >> 1 ^ ((X8_1 & 1) * 0xffffffff & 0xedb88320);
                X8_1 = tmp_20380_4;
                uint32_t tmp_lane_1000006d0_a_8_1 = X11_5;
                X11_5 = tmp_lane_1000006d0_a_8_1 - 1;
                if (tmp_lane_1000006d0_a_8_1 == 1) {
                    break;
                }
            }
            {
                X9_1++;
                if (X9_1 == X1_0) {
                    break;
                }
            }
        }
        return (uint64_t)~tmp_20380_4;
    }
}


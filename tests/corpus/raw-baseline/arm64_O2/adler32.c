uint64_t sym__adler32(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 65 source obligations: 51 rendered, 14 elided, 0 refused; 25 statements rendered */
    if (X1_0 == 0) {
        return 1;
    } else {
        uint64_t X8_1;
        uint64_t X9_1;
        uint32_t tmp_2b000_3;
        uint32_t tmp_2b000_2;
        X8_1 = 0;
        X9_1 = 1;
        uint32_t tmp_2a000_2 = 0x80078071;
        for (; ; ) {
            uint8_t* tmp_7400_2 = (uint8_t*)X0_0;
            X0_0++;
            uint8_t tmp_25400_2 = *tmp_7400_2;
            uint32_t tmp_12280_2 = (uint32_t)tmp_25400_2 + (uint32_t)X9_1;
            tmp_2b000_2 = tmp_12280_2 - (uint32_t)((uint64_t)tmp_12280_2 * (uint64_t)tmp_2a000_2 >> 47) * 0xfff1;
            X9_1 = (uint64_t)(uint32_t)tmp_2b000_2;
            uint32_t tmp_12280_3 = (uint32_t)X8_1 + tmp_2b000_2;
            tmp_2b000_3 = tmp_12280_3 - (uint32_t)((uint64_t)tmp_12280_3 * (uint64_t)tmp_2a000_2 >> 47) * 0xfff1;
            X8_1 = (uint64_t)(uint32_t)tmp_2b000_3;
            uint8_t TMPZR_4 = X1_0 == 1;
            X1_0--;
            uint8_t tmp_a00_2 = !TMPZR_4;
            if (!tmp_a00_2) {
                break;
            }
        }
        return (uint64_t)(tmp_2b000_3 << 16 | tmp_2b000_2);
    }
}


uint32_t sym__adler32(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 97 source obligations: 57 rendered, 40 elided, 0 refused; 35 statements rendered */
    {
        uint64_t stack_m32;
        uint32_t stack_m24;
        uint32_t stack_m20;
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t tmp_24c00_4;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m20 = 1;
        stack_m24 = 0;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= stack_m32;
            if (TMPCY_2) {
                break;
            } else {
                tmp_24c00_4 = stack_m20;
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                uint32_t tmp_12280_2 = (uint32_t)tmp_25600_2 + tmp_24c00_4;
                uint32_t tmp_42288_2 = tmp_12280_2 / 0xfff1;
                uint32_t tmp_3e480_2 = (0 ? 0 : tmp_42288_2) * 0xfff1;
                uint32_t tmp_3e580_2 = tmp_12280_2 - tmp_3e480_2;
                stack_m20 = tmp_3e580_2;
                tmp_24c00_4 = stack_m20;
                uint32_t tmp_12280_3 = tmp_24c00_4 + stack_m24;
                uint32_t tmp_42288_3 = tmp_12280_3 / 0xfff1;
                uint32_t tmp_2b380_3 = (0 ? 0 : tmp_42288_3) * 0xfff1;
                uint32_t tmp_3e480_3 = tmp_2b380_3;
                uint32_t tmp_3e580_3 = tmp_12280_3 - tmp_3e480_3;
                stack_m24 = tmp_3e580_3;
                {
                    uint64_t tmp_11f80_2 = stack_m32 + 1;
                    stack_m32 = tmp_11f80_2;
                }
            }
        }
        {
            tmp_24c00_4 = stack_m20;
            uint32_t tmp_2d500_1 = stack_m24 << 16 | tmp_24c00_4;
            return tmp_2d500_1;
        }
    }
}


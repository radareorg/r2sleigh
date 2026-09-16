uint32_t sym__adler32(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 84 source obligations: 55 rendered, 29 elided, 0 refused; 30 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t stack_m20;
        uint32_t stack_m24;
        uint64_t stack_m32;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m20 = 1;
        stack_m24 = 0;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t X8_3 = stack_m32;
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= X8_3;
            if (TMPCY_2) {
                break;
            } else {
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                uint32_t tmp_12280_2 = stack_m20 + (uint32_t)tmp_25600_2;
                uint32_t tmp_42288_2 = tmp_12280_2 / 0xfff1;
                uint32_t tmp_3e480_2 = (0 ? 0 : tmp_42288_2) * 0xfff1;
                stack_m20 = tmp_12280_2 - tmp_3e480_2;
                uint32_t tmp_12280_3 = stack_m24 + stack_m20;
                uint32_t tmp_42288_3 = tmp_12280_3 / 0xfff1;
                uint32_t tmp_2b380_3 = (0 ? 0 : tmp_42288_3) * 0xfff1;
                uint32_t tmp_3e480_3 = tmp_2b380_3;
                stack_m24 = tmp_12280_3 - tmp_3e480_3;
                {
                    uint64_t X8_11 = stack_m32;
                    stack_m32 = X8_11 + 1;
                }
            }
        }
        {
            uint32_t tmp_2d500_1 = stack_m20 | stack_m24 << 16;
            return tmp_2d500_1;
        }
    }
}


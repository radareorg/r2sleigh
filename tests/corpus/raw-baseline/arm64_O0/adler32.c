uint32_t sym__adler32(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 72 source obligations: 48 rendered, 24 elided, 0 refused; 19 statements rendered */
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
        for (stack_m32 = 0; stack_m32 < stack_m16; stack_m32++) {
            uint8_t tmp_25600_2 = stack_m8[stack_m32];
            uint32_t tmp_12280_2 = (uint32_t)tmp_25600_2 + stack_m20;
            uint32_t tmp_42288_2 = tmp_12280_2 / 0xfff1;
            stack_m20 = tmp_12280_2 - (0 ? 0 : tmp_42288_2) * 0xfff1;
            uint32_t tmp_12280_3 = stack_m20 + stack_m24;
            uint32_t tmp_42288_3 = tmp_12280_3 / 0xfff1;
            stack_m24 = tmp_12280_3 - (0 ? 0 : tmp_42288_3) * 0xfff1;
        }
        {
            return stack_m24 << 16 | stack_m20;
        }
    }
}


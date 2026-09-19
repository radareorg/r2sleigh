uint32_t sym__crc32_bitwise(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 74 source obligations: 44 rendered, 30 elided, 0 refused; 16 statements rendered */
    {
        uint64_t stack_m24;
        uint8_t* stack_m16;
        uint32_t stack_m28;
        uint64_t stack_m40;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = 0xffffffff;
        for (stack_m40 = 0; stack_m40 < stack_m24; stack_m40++) {
            uint32_t stack_m44;
            uint8_t tmp_11e00_2 = stack_m16[stack_m40];
            stack_m28 ^= (uint32_t)tmp_11e00_2;
            for (stack_m44 = 0; (int32_t)stack_m44 < 8; stack_m44++) {
                stack_m28 = stack_m28 >> 1 ^ (-(stack_m28 & 1) & 0xedb88320);
            }
        }
        return stack_m28 ^ 0xffffffff;
    }
}


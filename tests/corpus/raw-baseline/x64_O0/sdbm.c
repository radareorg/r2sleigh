uint32_t sym__sdbm(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 54 source obligations: 32 rendered, 22 elided, 0 refused; 12 statements rendered */
    {
        uint64_t stack_m24;
        uint8_t* stack_m16;
        uint32_t stack_m28;
        uint64_t stack_m40;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = 0;
        for (stack_m40 = 0; stack_m40 < stack_m24; stack_m40++) {
            uint8_t tmp_11e00_2 = stack_m16[stack_m40];
            stack_m28 = (uint32_t)tmp_11e00_2 + stack_m28 * 64 + stack_m28 * 0x10000 - stack_m28;
        }
        return stack_m28;
    }
}


uint32_t sym__sdbm(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 81 source obligations: 36 rendered, 45 elided, 0 refused; 13 statements rendered */
    {
        uint64_t stack_m40;
        uint32_t stack_m28;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = 0;
        stack_m40 = 0;
        while (stack_m40 < stack_m24) {
            uint8_t tmp_11e00_2 = stack_m16[stack_m40];
            stack_m28 = (uint32_t)tmp_11e00_2 + stack_m28 * 64 + stack_m28 * 0x10000 - stack_m28;
            stack_m40++;
        }
        return stack_m28;
    }
}


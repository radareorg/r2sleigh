uint32_t sym__djb2(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 75 source obligations: 33 rendered, 42 elided, 0 refused; 13 statements rendered */
    {
        uint64_t stack_m40;
        uint32_t stack_m28;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = 0x1505;
        stack_m40 = 0;
        while (stack_m40 < stack_m24) {
            uint8_t tmp_11e00_2 = stack_m16[stack_m40];
            stack_m28 = (uint32_t)tmp_11e00_2 + (stack_m28 * 32 + stack_m28);
            stack_m40++;
        }
        return stack_m28;
    }
}


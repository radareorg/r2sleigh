uint64_t sym__fnv1a64(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 51 source obligations: 29 rendered, 22 elided, 0 refused; 12 statements rendered */
    {
        uint64_t stack_m24;
        uint8_t* stack_m16;
        uint64_t stack_m32;
        uint64_t stack_m40;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m32 = 0xcbf29ce484222325U;
        for (stack_m40 = 0; stack_m40 < stack_m24; stack_m40++) {
            uint8_t tmp_11e00_2 = stack_m16[stack_m40];
            stack_m32 = (stack_m32 ^ (uint64_t)tmp_11e00_2) * 0x100000001b3;
        }
        return stack_m32;
    }
}


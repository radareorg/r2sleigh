uint32_t sym__sdbm(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 54 source obligations: 33 rendered, 21 elided, 0 refused; 12 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t stack_m20;
        uint64_t stack_m32;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m20 = 0;
        for (stack_m32 = 0; stack_m32 < stack_m16; stack_m32++) {
            uint8_t tmp_25600_2 = stack_m8[stack_m32];
            stack_m20 = stack_m20 * 64 + (uint32_t)tmp_25600_2 + stack_m20 * 0x10000 - stack_m20;
        }
        {
            return stack_m20;
        }
    }
}


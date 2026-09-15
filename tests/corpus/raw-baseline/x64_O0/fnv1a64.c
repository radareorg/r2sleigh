uint64_t sym__fnv1a64(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 79 source obligations: 37 rendered, 42 elided, 0 refused; 27 statements rendered */
    {
        uint64_t stack_m40;
        uint64_t stack_m32;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m32 = 0xcbf29ce484222325U;
        stack_m40 = 0;
        for (; ; ) {
            uint64_t RAX_3 = stack_m40;
            uint64_t tmp_3f800_2 = stack_m24;
            if (tmp_3f800_2 <= RAX_3) {
                break;
            } else {
                uint64_t RAX_10;
                int64_t RAX_7;
                uint64_t RCX_2 = stack_m40;
                uint8_t tmp_11e00_2 = stack_m16[RCX_2];
                uint64_t RAX_6 = stack_m32 ^ (uint64_t)tmp_11e00_2;
                stack_m32 = RAX_6;
                RAX_7 = 0x100000001b3;
                RAX_7 = (int64_t)((uint64_t)RAX_7 * stack_m32);
                stack_m32 = (uint64_t)RAX_7;
                RAX_10 = stack_m40;
                RAX_10++;
                stack_m40 = RAX_10;
            }
        }
        {
            uint64_t RAX_11 = stack_m32;
            return RAX_11;
        }
    }
}


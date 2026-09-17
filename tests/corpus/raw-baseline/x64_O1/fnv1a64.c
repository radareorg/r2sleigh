uint64_t sym__fnv1a64(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 46 source obligations: 26 rendered, 20 elided, 0 refused; 13 statements rendered */
    {
        int64_t R8_1;
        R8_1 = (int64_t)0xcbf29ce484222325U;
        if (RSI_0 == 0) {
            return (uint64_t)R8_1;
        } else {
            uint64_t RCX_1;
            RCX_1 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                R8_1 = (int64_t)(((uint64_t)R8_1 ^ (uint64_t)tmp_11e00_2) * 0x100000001b3);
                RCX_1++;
                if (RSI_0 == RCX_1) {
                    break;
                }
            }
            return (uint64_t)R8_1;
        }
    }
}


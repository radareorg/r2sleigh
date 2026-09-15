uint64_t sym__fnv1a64(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 47 source obligations: 26 rendered, 21 elided, 0 refused; 18 statements rendered */
    {
        int64_t R8_1;
        R8_1 = (int64_t)0xcbf29ce484222325U;
        uint64_t tmp_70500_1 = RSI_0;
        if (tmp_70500_1 == 0) {
            int64_t RAX_5 = R8_1;
            return (uint64_t)RAX_5;
        } else {
            uint64_t RCX_1;
            RCX_1 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                R8_1 = (int64_t)((uint64_t)R8_1 ^ (uint64_t)tmp_11e00_2);
                R8_1 = (int64_t)((uint64_t)R8_1 * 0x100000001b3);
                RCX_1++;
                uint64_t tmp_3f080_2 = RSI_0;
                uint8_t tmp_12800_2 = tmp_3f080_2 != RCX_1;
                if (!tmp_12800_2) {
                    break;
                }
            }
            return (uint64_t)R8_1;
        }
    }
}


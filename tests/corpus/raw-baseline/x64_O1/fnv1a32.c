uint64_t sym__fnv1a32(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 41 source obligations: 27 rendered, 14 elided, 0 refused; 12 statements rendered */
    {
        uint64_t RAX_1;
        RAX_1 = 0x811c9dc5;
        if (RSI_0 != 0) {
            uint64_t RCX_1;
            RCX_1 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                RAX_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_2 ^ (uint32_t)RAX_1) * 0x1000193);
                RCX_1++;
                if (RSI_0 == RCX_1) {
                    break;
                }
            }
        }
        return RAX_1;
    }
}


uint64_t sym__fnv1a32(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 125 source obligations: 96 rendered, 29 elided, 0 refused; 31 statements rendered */
    if (RSI_0 == 0) {
        return 0x811c9dc5;
    } else {
        uint64_t RAX_1;
        uint64_t RDX_1;
        uint64_t RCX_2 = (uint64_t)((uint32_t)RSI_0 & 3);
        if (4 <= RSI_0) {
            RSI_0 &= (uint64_t)-0x4;
            RAX_1 = 0x811c9dc5;
            RDX_1 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RDX_1];
                uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RDX_1 + 1];
                uint8_t tmp_11e00_4 = ((uint8_t*)RDI_0)[RDX_1 + 2];
                uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RDX_1 + 3];
                RAX_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_5 ^ (uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_4 ^ (uint32_t)((uint64_t)(int32_t)((uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_2 ^ (uint32_t)RAX_1) * 0x1000193) ^ (uint32_t)tmp_11e00_3) * 0x1000193)) * 0x1000193)) * 0x1000193);
                RDX_1 += 4;
                if (RSI_0 == RDX_1) {
                    break;
                }
            }
        } else {
            RAX_1 = 0x811c9dc5;
            RDX_1 = (uint64_t)0;
        }
        {
            if (RCX_2 != 0) {
                uint64_t RDX_6;
                RDI_0 += RDX_1;
                RDX_6 = (uint64_t)0;
                for (; ; ) {
                    uint8_t tmp_11e00_8 = ((uint8_t*)RDI_0)[RDX_6];
                    RAX_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_8 ^ (uint32_t)RAX_1) * 0x1000193);
                    RDX_6++;
                    if (RCX_2 == RDX_6) {
                        break;
                    }
                }
            }
            return RAX_1;
        }
    }
}


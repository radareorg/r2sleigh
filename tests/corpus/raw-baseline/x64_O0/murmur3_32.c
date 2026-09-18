uint32_t sym__murmur3_32(uint64_t RDI_0, uint64_t RSI_0, uint32_t EDX_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 205 source obligations: 142 rendered, 63 elided, 0 refused; 37 statements rendered */
    {
        uint64_t stack_m56;
        uint64_t stack_m48;
        int32_t stack_m28;
        uint64_t stack_m24;
        uint64_t stack_m16;
        int32_t tmp_11f00_1;
        uint64_t tmp_11f80_1;
        stack_m16 = RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = (int32_t)EDX_0;
        tmp_11f00_1 = (int32_t)stack_m28;
        tmp_11f80_1 = stack_m24;
        stack_m48 = tmp_11f80_1 >> 2;
        stack_m56 = 0;
        while (stack_m56 < stack_m48) {
            int32_t tmp_11f00_3 = (int32_t)((uint32_t*)stack_m16)[stack_m56];
            uint32_t RAX_9 = sym__rotl32((uint32_t)((uint64_t)tmp_11f00_3 * 0xffffffffcc9e2d51U), 15);
            uint32_t RAX_13 = sym__rotl32((uint32_t)((uint32_t)((uint64_t)(int32_t)RAX_9 * 0x1b873593) ^ (uint32_t)tmp_11f00_1), 13);
            tmp_11f00_1 = (int32_t)((uint32_t)((uint64_t)(int32_t)RAX_13 * 5) - 0x19ab949c);
            stack_m56++;
        }
        {
            int32_t stack_m76;
            uint64_t tmp_4a00_3 = stack_m48 * 4 + stack_m16;
            stack_m76 = 0;
            tmp_11f80_1 = stack_m24;
            switch ((uint64_t)((uint32_t)tmp_11f80_1 & 3)) {
            case 3:
                {
                    uint8_t tmp_11e00_1 = *(uint8_t*)(tmp_4a00_3 + 2);
                    stack_m76 = (int32_t)((uint32_t)tmp_11e00_1 << 16 ^ (uint32_t)stack_m76);
                }
            case 2:
                {
                    uint8_t tmp_11e00_3 = *(uint8_t*)(tmp_4a00_3 + 1);
                    stack_m76 = (int32_t)((uint32_t)tmp_11e00_3 << 8 ^ (uint32_t)stack_m76);
                }
            case 1:
                {
                    uint8_t tmp_11e00_5 = *(uint8_t*)tmp_4a00_3;
                    uint32_t RAX_41 = sym__rotl32((uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_5 ^ (uint32_t)stack_m76) * 0xffffffffcc9e2d51U), 15);
                    tmp_11f00_1 = (int32_t)((uint32_t)((uint64_t)(int32_t)RAX_41 * 0x1b873593) ^ (uint32_t)tmp_11f00_1);
                }
            default:
                {
                    tmp_11f80_1 = stack_m24;
                    uint32_t tmp_lane_100000aac_7_3b_1 = (uint32_t)tmp_11f80_1 ^ (uint32_t)tmp_11f00_1;
                    uint32_t tmp_lane_100000aac_50_46_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000aac_7_3b_1 >> 16 ^ tmp_lane_100000aac_7_3b_1) * 0xffffffff85ebca6bU);
                    uint32_t tmp_lane_100000aac_97_50_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000aac_50_46_1 >> 13 ^ tmp_lane_100000aac_50_46_1) * 0xffffffffc2b2ae35U);
                    return tmp_lane_100000aac_97_50_1 >> 16 ^ tmp_lane_100000aac_97_50_1;
                }
            }
        }
    }
}


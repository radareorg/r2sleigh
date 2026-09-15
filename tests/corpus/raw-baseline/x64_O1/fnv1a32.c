uint64_t sym__fnv1a32(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 41 source obligations: 26 rendered, 15 elided, 0 refused; 20 statements rendered */
    {
        uint64_t RAX_1;
        RAX_1 = 0x811c9dc5;
        uint64_t tmp_70500_1 = RSI_0;
        uint8_t ZF_1 = tmp_70500_1 == 0;
        if (!ZF_1) {
            uint64_t RCX_1;
            RCX_1 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                uint32_t tmp_lane_100000570_3_3_1 = (uint32_t)tmp_11e00_2;
                int32_t tmp_lane_100000570_7_6_1 = (int32_t)((uint32_t)RAX_1 ^ tmp_lane_100000570_3_3_1);
                uint64_t tmp_4c780_2 = (uint64_t)tmp_lane_100000570_7_6_1 * 0x1000193;
                int32_t tmp_lane_100000570_12_9_1 = (int32_t)tmp_4c780_2;
                RAX_1 = (uint64_t)(uint32_t)tmp_lane_100000570_12_9_1;
                RCX_1++;
                uint64_t tmp_3f080_2 = RSI_0;
                uint8_t ZF_6 = tmp_3f080_2 == RCX_1;
                if (ZF_6) {
                    break;
                }
            }
        }
        return RAX_1;
    }
}


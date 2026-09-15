uint32_t sym__fnv1a32(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 77 source obligations: 36 rendered, 41 elided, 0 refused; 24 statements rendered */
    {
        uint64_t stack_m40;
        int32_t stack_m28;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = -2128831035;
        stack_m40 = 0;
        for (; ; ) {
            uint64_t RAX_2 = stack_m40;
            uint64_t tmp_3f800_2 = stack_m24;
            if (tmp_3f800_2 <= RAX_2) {
                break;
            } else {
                uint64_t RAX_8;
                uint8_t tmp_11e00_2 = stack_m16[stack_m40];
                int32_t tmp_lane_100000585_f_2_1 = (int32_t)((uint32_t)tmp_11e00_2 ^ (uint32_t)stack_m28);
                stack_m28 = tmp_lane_100000585_f_2_1;
                uint64_t tmp_4c780_2 = (uint64_t)stack_m28 * 0x1000193;
                int32_t tmp_lane_100000585_1f_5_1 = (int32_t)tmp_4c780_2;
                stack_m28 = tmp_lane_100000585_1f_5_1;
                RAX_8 = stack_m40;
                RAX_8++;
                stack_m40 = RAX_8;
            }
        }
        return (uint32_t)stack_m28;
    }
}


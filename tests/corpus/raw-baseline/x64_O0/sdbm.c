uint32_t sym__sdbm(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 81 source obligations: 36 rendered, 45 elided, 0 refused; 27 statements rendered */
    {
        uint64_t stack_m40;
        uint32_t stack_m28;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = 0;
        stack_m40 = 0;
        for (; ; ) {
            uint64_t RAX_2 = stack_m40;
            uint64_t tmp_3f800_2 = stack_m24;
            uint8_t CF_2 = RAX_2 < tmp_3f800_2;
            if (!CF_2) {
                break;
            } else {
                uint64_t RAX_9;
                uint8_t tmp_11e00_2 = stack_m16[stack_m40];
                uint32_t tmp_lane_1000006b5_9_0_1 = (uint32_t)tmp_11e00_2;
                uint32_t tmp_lane_1000006b5_11_3_1 = stack_m28 << 6;
                uint32_t tmp_lane_1000006b5_37_7_1 = tmp_lane_1000006b5_9_0_1 + tmp_lane_1000006b5_11_3_1;
                uint32_t tmp_lane_1000006b5_45_b_1 = stack_m28 << 16;
                uint32_t tmp_lane_1000006b5_6b_f_1 = tmp_lane_1000006b5_37_7_1 + tmp_lane_1000006b5_45_b_1;
                uint32_t tmp_lane_1000006b5_79_12_1 = tmp_lane_1000006b5_6b_f_1 - stack_m28;
                stack_m28 = tmp_lane_1000006b5_79_12_1;
                RAX_9 = stack_m40;
                RAX_9++;
                stack_m40 = RAX_9;
            }
        }
        return stack_m28;
    }
}


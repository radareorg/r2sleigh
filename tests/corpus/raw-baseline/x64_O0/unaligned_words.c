uint32_t sym__unaligned_words(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 126 source obligations: 63 rendered, 63 elided, 0 refused; 46 statements rendered */
    {
        uint64_t stack_m40;
        int32_t stack_m28;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = -1640531527;
        stack_m40 = 0;
        for (; ; ) {
            uint64_t RAX_2;
            RAX_2 = stack_m40;
            RAX_2 += 8;
            uint64_t tmp_3f800_2 = stack_m24;
            uint8_t CF_3 = RAX_2 < tmp_3f800_2;
            uint8_t ZF_3 = RAX_2 == tmp_3f800_2;
            if (!(CF_3 || ZF_3)) {
                break;
            } else {
                int32_t stack_m44;
                uint64_t RAX_10;
                uint64_t RCX_2 = stack_m40;
                int32_t tmp_11f00_2 = (int32_t)*(uint32_t*)((uint64_t)stack_m16 + RCX_2 + 1);
                stack_m44 = tmp_11f00_2;
                int32_t tmp_lane_1000017f9_17_4_1 = (int32_t)((uint32_t)stack_m28 ^ (uint32_t)stack_m44);
                uint64_t tmp_4c780_2 = (uint64_t)tmp_lane_1000017f9_17_4_1 * 0x1000193;
                int32_t tmp_lane_1000017f9_22_7_1 = (int32_t)tmp_4c780_2;
                stack_m28 = tmp_lane_1000017f9_22_7_1;
                RAX_10 = stack_m40;
                RAX_10 += 7;
                stack_m40 = RAX_10;
            }
        }
        {
            for (; ; ) {
                uint64_t RAX_12 = stack_m40;
                uint64_t tmp_3f800_4 = stack_m24;
                if (tmp_3f800_4 <= RAX_12) {
                    break;
                } else {
                    uint64_t RAX_17;
                    uint64_t RDX_2 = stack_m40;
                    uint8_t tmp_11e00_2 = stack_m16[RDX_2];
                    uint32_t tmp_lane_100001831_d_a_1 = (uint32_t)tmp_11e00_2;
                    int32_t tmp_lane_100001831_11_d_1 = (int32_t)((uint32_t)stack_m28 ^ tmp_lane_100001831_d_a_1);
                    uint64_t tmp_4c780_4 = (uint64_t)tmp_lane_100001831_11_d_1 * 0x1000193;
                    int32_t tmp_lane_100001831_1c_10_1 = (int32_t)tmp_4c780_4;
                    stack_m28 = tmp_lane_100001831_1c_10_1;
                    RAX_17 = stack_m40;
                    RAX_17++;
                    stack_m40 = RAX_17;
                }
            }
            return (uint32_t)stack_m28;
        }
    }
}


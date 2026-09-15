uint32_t sym__pearson(uint64_t RDI_0, uint64_t RSI_0)
{
#define _pearson_tab__r2sleigh_addr 0x100001a50ULL
    extern char _pearson_tab[];

    /* r2dec proof: no individual construct is marked; 75 source obligations: 38 rendered, 37 elided, 0 refused; 27 statements rendered; 1 data object type refused */
    {
        uint64_t stack_m40;
        uint8_t stack_m25;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m25 = 0;
        stack_m40 = 0;
        for (; ; ) {
            uint64_t RAX_2 = stack_m40;
            uint64_t tmp_3f800_2 = stack_m24;
            if (tmp_3f800_2 <= RAX_2) {
                break;
            } else {
                uint64_t RAX_8;
                uint32_t tmp_lane_1000016f2_2_0_1 = (uint32_t)stack_m25;
                uint64_t RDX_2 = stack_m40;
                uint8_t tmp_11e00_3 = stack_m16[RDX_2];
                uint32_t tmp_lane_1000016f2_d_1_1 = (uint32_t)tmp_11e00_3;
                int32_t tmp_lane_1000016f2_11_4_1 = (int32_t)(tmp_lane_1000016f2_2_0_1 ^ tmp_lane_1000016f2_d_1_1);
                uint64_t RCX_4 = (uint64_t)(int32_t)tmp_lane_1000016f2_11_4_1;
                uint8_t tmp_11e00_4 = *(uint8_t*)(RCX_4 + (uint64_t)&_pearson_tab);
                stack_m25 = tmp_11e00_4;
                RAX_8 = stack_m40;
                RAX_8++;
                stack_m40 = RAX_8;
            }
        }
        {
            uint32_t tmp_lane_100001722_2_9_1 = (uint32_t)stack_m25;
            return tmp_lane_100001722_2_9_1;
        }
    }
}


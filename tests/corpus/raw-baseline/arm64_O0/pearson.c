uint8_t sym__pearson(uint64_t X0_0, uint64_t X1_0)
{
#define _pearson_tab__r2sleigh_addr 0x100001f68ULL
    extern char _pearson_tab[];

    /* r2dec proof: no individual construct is marked; 76 source obligations: 52 rendered, 24 elided, 0 refused; 22 statements rendered; 1 data object type refused */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint8_t stack_m17;
        uint64_t stack_m32;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m17 = 0;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t X8_2 = stack_m32;
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= X8_2;
            if (TMPCY_2) {
                break;
            } else {
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                int32_t tmp_20380_2 = (int32_t)((uint32_t)stack_m17 ^ (uint32_t)tmp_25600_2);
                uint8_t tmp_25500_3 = *(uint8_t*)((uint64_t)tmp_20380_2 + (uint64_t)&_pearson_tab);
                stack_m17 = tmp_25500_3;
                {
                    uint64_t X8_9 = stack_m32;
                    stack_m32 = X8_9 + 1;
                }
            }
        }
        {
            uint8_t tmp_25500_4 = stack_m17;
            return tmp_25500_4;
        }
    }
}


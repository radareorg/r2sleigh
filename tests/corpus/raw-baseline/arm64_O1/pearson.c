uint64_t sym__pearson(uint64_t X0_0, uint64_t X1_0)
{
#define _pearson_tab__r2sleigh_addr 0x100000ec0ULL
    extern char _pearson_tab[];

    /* r2dec proof: no individual construct is marked; 45 source obligations: 35 rendered, 10 elided, 0 refused; 15 statements rendered; 1 data object type refused */
    {
        uint64_t X8_1;
        X8_1 = 0;
        if (X1_0 != 0) {
            uint64_t X9_2 = (uint64_t)&_pearson_tab;
            for (; ; ) {
                uint8_t* tmp_7400_2 = (uint8_t*)X0_0;
                X0_0++;
                uint8_t tmp_25400_2 = *tmp_7400_2;
                uint8_t tmp_25600_2 = *(uint8_t*)(((uint64_t)((uint32_t)tmp_25400_2 ^ (uint32_t)X8_1) & 255) + X9_2);
                X8_1 = (uint64_t)tmp_25600_2;
                uint8_t TMPZR_3 = X1_0 == 1;
                X1_0--;
                if (TMPZR_3) {
                    break;
                }
            }
        }
        return X8_1;
    }
}


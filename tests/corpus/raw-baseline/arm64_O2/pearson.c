uint64_t sym__pearson(uint64_t X0_0, uint64_t X1_0)
{
#define _pearson_tab__r2sleigh_addr 0x100001040ULL
    extern char _pearson_tab[];

    /* r2dec proof: no individual construct is marked; 47 source obligations: 37 rendered, 10 elided, 0 refused; 21 statements rendered; 1 data object type refused */
    {
        uint64_t X8_1;
        uint64_t X1_1;
        X8_1 = 0;
        X1_1 = X1_0;
        if (X1_0 != 0) {
            uint64_t tmp_11f80_1 = (uint64_t)&_pearson_tab;
            uint64_t X9_2 = tmp_11f80_1;
            for (; ; ) {
                uint8_t* tmp_7400_2 = (uint8_t*)X0_0;
                X0_0++;
                uint8_t tmp_25400_2 = *tmp_7400_2;
                uint8_t tmp_25600_2 = *(uint8_t*)(((uint64_t)((uint32_t)tmp_25400_2 ^ (uint32_t)X8_1) & 255) + X9_2);
                X8_1 = (uint64_t)(uint8_t)tmp_25600_2;
                uint64_t tmp_3e280_2 = X1_1 - 1;
                uint8_t TMPZR_3 = X1_1 == 1;
                uint64_t X1_2 = tmp_3e280_2;
                uint8_t tmp_a00_2 = !TMPZR_3;
                X1_1 = X1_2;
                if (!tmp_a00_2) {
                    break;
                }
            }
        }
        return X8_1;
    }
}


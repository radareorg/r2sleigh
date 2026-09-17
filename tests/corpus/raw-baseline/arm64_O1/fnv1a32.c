uint64_t sym__fnv1a32(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 39 source obligations: 29 rendered, 10 elided, 0 refused; 16 statements rendered */
    {
        uint8_t* X8_1;
        uint64_t X0_2;
        X8_1 = (uint8_t*)X0_0;
        X0_2 = (uint64_t)0x811c9dc5;
        if (X1_0 != 0) {
            uint32_t tmp_2a000_4 = 0x1000193;
            for (; ; ) {
                uint8_t* tmp_7400_2 = X8_1;
                X8_1 = (uint8_t*)((uint64_t)X8_1 + 1);
                uint8_t tmp_25400_2 = *tmp_7400_2;
                X0_2 = (uint64_t)(((uint32_t)X0_2 ^ (uint32_t)tmp_25400_2) * tmp_2a000_4);
                uint8_t TMPZR_2 = X1_0 == 1;
                X1_0--;
                if (TMPZR_2) {
                    break;
                }
            }
        }
        return X0_2;
    }
}


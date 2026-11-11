/*--[ fs-ml-model.h ]----------------------------------------------------
 * Neural Sentinel: Auto-generated INT8 GBDT Model Header (Iterative Active Learning)
 * Test F1 Score: 1.0000
 *--------------------------------------------------------------------*/
#ifndef FS_ML_MODEL_H
#define FS_ML_MODEL_H

#include <glib.h>

#define FS_ML_N_ESTIMATORS 26
#define FS_ML_N_CLASSES 4

typedef struct {
    gint   feature_idx;
    gint16 threshold;
    gint   left_child;
    gint   right_child;
    gint16 value;
} FsMlTreeNode;

static inline gint
fs_ml_evaluate_tree_ensemble (const gint8 *x)
{
    /* Integer-quantized multi-class logit accumulation */
    gint logits[4] = {0, 0, 0, 0};

    /* Tree 0 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            if (x[0] <= 2) {
                logits[0] += 123;
            } else {
                logits[0] += 123;
            }
        } else {
            if (x[0] <= 16) {
                logits[0] += -190;
            } else {
                logits[0] += -190;
            }
        }
    } else {
        if (x[10] <= 594) {
            logits[0] += -190;
        } else {
            if (x[10] <= 624) {
                logits[0] += -190;
            } else {
                logits[0] += -190;
            }
        }
    }
    /* Tree 1 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 114;
        } else {
            logits[0] += -153;
        }
    } else {
        if (x[1] <= 819) {
            logits[0] += -154;
        } else {
            logits[0] += -155;
        }
    }
    /* Tree 2 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 107;
        } else {
            if (x[5] <= 129) {
                logits[0] += -134;
            } else {
                logits[0] += -134;
            }
        }
    } else {
        if (x[9] <= 701) {
            if (x[12] <= 150) {
                logits[0] += -135;
            } else {
                logits[0] += -135;
            }
        } else {
            logits[0] += -134;
        }
    }
    /* Tree 3 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 101;
        } else {
            logits[0] += -121;
        }
    } else {
        if (x[2] <= 225) {
            if (x[6] <= 617) {
                logits[0] += -121;
            } else {
                logits[0] += -121;
            }
        } else {
            if (x[6] <= 250) {
                logits[0] += -121;
            } else {
                logits[0] += -121;
            }
        }
    }
    /* Tree 4 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 97;
        } else {
            logits[0] += -112;
        }
    } else {
        if (x[2] <= 225) {
            logits[0] += -112;
        } else {
            logits[0] += -112;
        }
    }
    /* Tree 5 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            if (x[8] <= 0) {
                logits[0] += 93;
            } else {
                logits[0] += 93;
            }
        } else {
            if (x[7] <= 276) {
                logits[0] += -105;
            } else {
                logits[0] += -105;
            }
        }
    } else {
        if (x[2] <= 225) {
            if (x[12] <= 50) {
                logits[0] += -105;
            } else {
                logits[0] += -105;
            }
        } else {
            logits[0] += -105;
        }
    }
    /* Tree 6 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            if (x[2] <= 37) {
                logits[0] += 90;
            } else {
                logits[0] += 90;
            }
        } else {
            logits[0] += -100;
        }
    } else {
        if (x[1] <= 819) {
            logits[0] += -100;
        } else {
            if (x[5] <= 506) {
                logits[0] += -99;
            } else {
                logits[0] += -99;
            }
        }
    }
    /* Tree 7 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 88;
        } else {
            logits[0] += -95;
        }
    } else {
        if (x[1] <= 819) {
            logits[0] += -95;
        } else {
            logits[0] += -95;
        }
    }
    /* Tree 8 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 86;
        } else {
            logits[0] += -92;
        }
    } else {
        if (x[1] <= 819) {
            logits[0] += -92;
        } else {
            if (x[0] <= 1091) {
                logits[0] += -92;
            } else {
                logits[0] += -92;
            }
        }
    }
    /* Tree 9 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 84;
        } else {
            logits[0] += -89;
        }
    } else {
        if (x[9] <= 701) {
            if (x[6] <= 188) {
                logits[0] += -89;
            } else {
                logits[0] += -89;
            }
        } else {
            logits[0] += -89;
        }
    }
    /* Tree 10 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 83;
        } else {
            logits[0] += -87;
        }
    } else {
        if (x[1] <= 819) {
            if (x[4] <= 1553) {
                logits[0] += -87;
            } else {
                logits[0] += -87;
            }
        } else {
            logits[0] += -87;
        }
    }
    /* Tree 11 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            if (x[7] <= 158) {
                logits[0] += 81;
            } else {
                logits[0] += 81;
            }
        } else {
            if (x[11] <= 9) {
                logits[0] += -85;
            } else {
                logits[0] += -85;
            }
        }
    } else {
        if (x[9] <= 701) {
            logits[0] += -85;
        } else {
            logits[0] += -85;
        }
    }
    /* Tree 12 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 80;
        } else {
            logits[0] += -83;
        }
    } else {
        if (x[9] <= 701) {
            if (x[9] <= 2) {
                logits[0] += -83;
            } else {
                logits[0] += -83;
            }
        } else {
            if (x[5] <= 153) {
                logits[0] += -83;
            } else {
                logits[0] += -83;
            }
        }
    }
    /* Tree 13 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 79;
        } else {
            logits[0] += -82;
        }
    } else {
        if (x[1] <= 819) {
            logits[0] += -82;
        } else {
            if (x[7] <= 137) {
                logits[0] += -82;
            } else {
                logits[0] += -82;
            }
        }
    }
    /* Tree 14 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 79;
        } else {
            if (x[9] <= 0) {
                logits[0] += -81;
            } else {
                logits[0] += -81;
            }
        }
    } else {
        if (x[1] <= 819) {
            logits[0] += -81;
        } else {
            logits[0] += -81;
        }
    }
    /* Tree 15 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 78;
        } else {
            if (x[1] <= 338) {
                logits[0] += -80;
            } else {
                logits[0] += -80;
            }
        }
    } else {
        if (x[9] <= 701) {
            logits[0] += -80;
        } else {
            logits[0] += -80;
        }
    }
    /* Tree 16 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 78;
        } else {
            logits[0] += -79;
        }
    } else {
        if (x[9] <= 701) {
            logits[0] += -79;
        } else {
            logits[0] += -79;
        }
    }
    /* Tree 17 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 77;
        } else {
            logits[0] += -78;
        }
    } else {
        if (x[9] <= 701) {
            logits[0] += -78;
        } else {
            logits[0] += -78;
        }
    }
    /* Tree 18 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 77;
        } else {
            logits[0] += -78;
        }
    } else {
        if (x[9] <= 701) {
            logits[0] += -78;
        } else {
            logits[0] += -78;
        }
    }
    /* Tree 19 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 76;
        } else {
            logits[0] += -77;
        }
    } else {
        if (x[9] <= 701) {
            logits[0] += -77;
        } else {
            logits[0] += -77;
        }
    }
    /* Tree 20 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 76;
        } else {
            if (x[5] <= 333) {
                logits[0] += -77;
            } else {
                logits[0] += -77;
            }
        }
    } else {
        if (x[2] <= 225) {
            logits[0] += -77;
        } else {
            logits[0] += -77;
        }
    }
    /* Tree 21 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 76;
        } else {
            logits[0] += -77;
        }
    } else {
        if (x[1] <= 819) {
            logits[0] += -77;
        } else {
            logits[0] += -77;
        }
    }
    /* Tree 22 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 76;
        } else {
            logits[0] += -76;
        }
    } else {
        if (x[2] <= 225) {
            logits[0] += -76;
        } else {
            logits[0] += -76;
        }
    }
    /* Tree 23 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 76;
        } else {
            logits[0] += -76;
        }
    } else {
        if (x[9] <= 701) {
            logits[0] += -76;
        } else {
            logits[0] += -76;
        }
    }
    /* Tree 24 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 75;
        } else {
            logits[0] += -76;
        }
    } else {
        if (x[9] <= 701) {
            logits[0] += -76;
        } else {
            logits[0] += -76;
        }
    }
    /* Tree 25 for class 0 */
    if (x[10] <= 154) {
        if (x[8] <= 1275) {
            logits[0] += 75;
        } else {
            logits[0] += -76;
        }
    } else {
        if (x[2] <= 225) {
            logits[0] += -76;
        } else {
            logits[0] += -76;
        }
    }
    /* Tree 0 for class 1 */
    if (x[2] <= 300) {
        if (x[1] <= 282) {
            logits[1] += -88;
        } else {
            logits[1] += -88;
        }
    } else {
        logits[1] += 501;
    }
    /* Tree 1 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -86;
            } else {
                logits[1] += -87;
            }
        } else {
            if (x[9] <= 701) {
                logits[1] += -87;
            } else {
                logits[1] += -87;
            }
        }
    } else {
        logits[1] += 295;
    }
    /* Tree 2 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -84;
            } else {
                logits[1] += -86;
            }
        } else {
            if (x[10] <= 136) {
                logits[1] += -86;
            } else {
                logits[1] += -86;
            }
        }
    } else {
        logits[1] += 218;
    }
    /* Tree 3 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -83;
            } else {
                logits[1] += -84;
            }
        } else {
            if (x[0] <= 193) {
                logits[1] += -84;
            } else {
                logits[1] += -85;
            }
        }
    } else {
        logits[1] += 177;
    }
    /* Tree 4 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -82;
            } else {
                logits[1] += -83;
            }
        } else {
            if (x[8] <= 1438) {
                logits[1] += -83;
            } else {
                logits[1] += -83;
            }
        }
    } else {
        logits[1] += 151;
    }
    /* Tree 5 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -81;
            } else {
                logits[1] += -82;
            }
        } else {
            if (x[9] <= 701) {
                logits[1] += -82;
            } else {
                logits[1] += -82;
            }
        }
    } else {
        if (x[10] <= 781) {
            logits[1] += 134;
        } else {
            logits[1] += 134;
        }
    }
    /* Tree 6 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -80;
            } else {
                logits[1] += -81;
            }
        } else {
            if (x[0] <= 193) {
                logits[1] += -81;
            } else {
                logits[1] += -81;
            }
        }
    } else {
        if (x[1] <= 1011) {
            logits[1] += 122;
        } else {
            logits[1] += 122;
        }
    }
    /* Tree 7 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -79;
            } else {
                logits[1] += -80;
            }
        } else {
            if (x[8] <= 1438) {
                logits[1] += -80;
            } else {
                logits[1] += -80;
            }
        }
    } else {
        logits[1] += 113;
    }
    /* Tree 8 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -78;
            } else {
                logits[1] += -80;
            }
        } else {
            if (x[8] <= 1438) {
                logits[1] += -80;
            } else {
                logits[1] += -80;
            }
        }
    } else {
        if (x[7] <= 204) {
            logits[1] += 106;
        } else {
            if (x[7] <= 209) {
                logits[1] += 106;
            } else {
                logits[1] += 106;
            }
        }
    }
    /* Tree 9 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -78;
            } else {
                logits[1] += -79;
            }
        } else {
            if (x[10] <= 136) {
                logits[1] += -79;
            } else {
                logits[1] += -79;
            }
        }
    } else {
        logits[1] += 100;
    }
    /* Tree 10 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -77;
            } else {
                logits[1] += -78;
            }
        } else {
            if (x[8] <= 1438) {
                logits[1] += -78;
            } else {
                logits[1] += -78;
            }
        }
    } else {
        if (x[0] <= 806) {
            logits[1] += 96;
        } else {
            if (x[5] <= 309) {
                logits[1] += 96;
            } else {
                logits[1] += 96;
            }
        }
    }
    /* Tree 11 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -77;
            } else {
                logits[1] += -78;
            }
        } else {
            if (x[8] <= 1438) {
                logits[1] += -78;
            } else {
                logits[1] += -78;
            }
        }
    } else {
        logits[1] += 92;
    }
    /* Tree 12 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -77;
            } else {
                logits[1] += -77;
            }
        } else {
            if (x[10] <= 136) {
                logits[1] += -77;
            } else {
                logits[1] += -77;
            }
        }
    } else {
        if (x[6] <= 291) {
            logits[1] += 89;
        } else {
            logits[1] += 89;
        }
    }
    /* Tree 13 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -76;
            } else {
                logits[1] += -77;
            }
        } else {
            if (x[0] <= 193) {
                logits[1] += -77;
            } else {
                logits[1] += -77;
            }
        }
    } else {
        logits[1] += 87;
    }
    /* Tree 14 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -76;
            } else {
                logits[1] += -77;
            }
        } else {
            if (x[9] <= 701) {
                logits[1] += -77;
            } else {
                logits[1] += -77;
            }
        }
    } else {
        if (x[5] <= 163) {
            logits[1] += 85;
        } else {
            if (x[4] <= 1554) {
                logits[1] += 85;
            } else {
                logits[1] += 85;
            }
        }
    }
    /* Tree 15 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -76;
            } else {
                logits[1] += -76;
            }
        } else {
            if (x[10] <= 136) {
                logits[1] += -76;
            } else {
                logits[1] += -76;
            }
        }
    } else {
        logits[1] += 84;
    }
    /* Tree 16 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -76;
            } else {
                logits[1] += -76;
            }
        } else {
            if (x[10] <= 136) {
                logits[1] += -76;
            } else {
                logits[1] += -76;
            }
        }
    } else {
        logits[1] += 82;
    }
    /* Tree 17 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -75;
            } else {
                logits[1] += -76;
            }
        } else {
            if (x[8] <= 1438) {
                logits[1] += -76;
            } else {
                logits[1] += -76;
            }
        }
    } else {
        if (x[8] <= 2) {
            logits[1] += 81;
        } else {
            logits[1] += 81;
        }
    }
    /* Tree 18 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -75;
            } else {
                logits[1] += -76;
            }
        } else {
            if (x[8] <= 1438) {
                logits[1] += -76;
            } else {
                logits[1] += -76;
            }
        }
    } else {
        logits[1] += 80;
    }
    /* Tree 19 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -75;
            } else {
                logits[1] += -76;
            }
        } else {
            if (x[0] <= 193) {
                logits[1] += -76;
            } else {
                logits[1] += -76;
            }
        }
    } else {
        if (x[12] <= 50) {
            logits[1] += 79;
        } else {
            logits[1] += 79;
        }
    }
    /* Tree 20 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        } else {
            if (x[9] <= 701) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        }
    } else {
        logits[1] += 79;
    }
    /* Tree 21 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        } else {
            if (x[0] <= 193) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        }
    } else {
        logits[1] += 78;
    }
    /* Tree 22 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        } else {
            if (x[8] <= 1438) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        }
    } else {
        logits[1] += 77;
    }
    /* Tree 23 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        } else {
            if (x[10] <= 136) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        }
    } else {
        logits[1] += 77;
    }
    /* Tree 24 for class 1 */
    if (x[1] <= 819) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        } else {
            if (x[8] <= 1438) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        }
    } else {
        logits[1] += 77;
    }
    /* Tree 25 for class 1 */
    if (x[2] <= 300) {
        if (x[9] <= 127) {
            if (x[8] <= 1275) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        } else {
            if (x[10] <= 136) {
                logits[1] += -75;
            } else {
                logits[1] += -75;
            }
        }
    } else {
        logits[1] += 76;
    }
    /* Tree 0 for class 2 */
    if (x[9] <= 701) {
        logits[2] += -86;
    } else {
        if (x[7] <= 242) {
            logits[2] += 568;
        } else {
            if (x[11] <= 8) {
                logits[2] += 568;
            } else {
                logits[2] += 568;
            }
        }
    }
    /* Tree 1 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -84;
            } else {
                logits[2] += -85;
            }
        } else {
            if (x[8] <= 3) {
                logits[2] += -85;
            } else {
                logits[2] += -85;
            }
        }
    } else {
        logits[2] += 313;
    }
    /* Tree 2 for class 2 */
    if (x[9] <= 701) {
        if (x[1] <= 819) {
            if (x[8] <= 1275) {
                logits[2] += -83;
            } else {
                logits[2] += -84;
            }
        } else {
            logits[2] += -84;
        }
    } else {
        logits[2] += 227;
    }
    /* Tree 3 for class 2 */
    if (x[9] <= 701) {
        if (x[1] <= 819) {
            if (x[8] <= 1275) {
                logits[2] += -82;
            } else {
                logits[2] += -83;
            }
        } else {
            logits[2] += -83;
        }
    } else {
        if (x[7] <= 285) {
            if (x[4] <= 1538) {
                logits[2] += 183;
            } else {
                logits[2] += 183;
            }
        } else {
            logits[2] += 183;
        }
    }
    /* Tree 4 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -81;
            } else {
                logits[2] += -82;
            }
        } else {
            logits[2] += -82;
        }
    } else {
        logits[2] += 155;
    }
    /* Tree 5 for class 2 */
    if (x[9] <= 701) {
        if (x[10] <= 408) {
            if (x[8] <= 1275) {
                logits[2] += -80;
            } else {
                logits[2] += -81;
            }
        } else {
            logits[2] += -81;
        }
    } else {
        if (x[1] <= 346) {
            logits[2] += 137;
        } else {
            logits[2] += 137;
        }
    }
    /* Tree 6 for class 2 */
    if (x[9] <= 701) {
        if (x[10] <= 408) {
            if (x[8] <= 1275) {
                logits[2] += -79;
            } else {
                logits[2] += -81;
            }
        } else {
            if (x[10] <= 800) {
                logits[2] += -81;
            } else {
                logits[2] += -81;
            }
        }
    } else {
        if (x[10] <= 260) {
            logits[2] += 124;
        } else {
            if (x[6] <= 571) {
                logits[2] += 124;
            } else {
                logits[2] += 124;
            }
        }
    }
    /* Tree 7 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -78;
            } else {
                logits[2] += -80;
            }
        } else {
            if (x[7] <= 362) {
                logits[2] += -80;
            } else {
                logits[2] += -80;
            }
        }
    } else {
        logits[2] += 114;
    }
    /* Tree 8 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -78;
            } else {
                logits[2] += -79;
            }
        } else {
            if (x[10] <= 828) {
                logits[2] += -79;
            } else {
                logits[2] += -79;
            }
        }
    } else {
        if (x[5] <= 129) {
            logits[2] += 107;
        } else {
            logits[2] += 107;
        }
    }
    /* Tree 9 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -77;
            } else {
                logits[2] += -79;
            }
        } else {
            if (x[5] <= 371) {
                logits[2] += -78;
            } else {
                logits[2] += -78;
            }
        }
    } else {
        logits[2] += 101;
    }
    /* Tree 10 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -77;
            } else {
                logits[2] += -78;
            }
        } else {
            logits[2] += -78;
        }
    } else {
        logits[2] += 97;
    }
    /* Tree 11 for class 2 */
    if (x[9] <= 701) {
        if (x[1] <= 819) {
            if (x[8] <= 1275) {
                logits[2] += -77;
            } else {
                logits[2] += -78;
            }
        } else {
            if (x[7] <= 116) {
                logits[2] += -77;
            } else {
                logits[2] += -77;
            }
        }
    } else {
        logits[2] += 93;
    }
    /* Tree 12 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -76;
            } else {
                logits[2] += -77;
            }
        } else {
            if (x[10] <= 790) {
                logits[2] += -77;
            } else {
                logits[2] += -77;
            }
        }
    } else {
        if (x[11] <= 2) {
            logits[2] += 90;
        } else {
            logits[2] += 90;
        }
    }
    /* Tree 13 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -76;
            } else {
                logits[2] += -77;
            }
        } else {
            if (x[0] <= 802) {
                logits[2] += -77;
            } else {
                logits[2] += -77;
            }
        }
    } else {
        if (x[4] <= 1534) {
            logits[2] += 88;
        } else {
            logits[2] += 88;
        }
    }
    /* Tree 14 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -76;
            } else {
                logits[2] += -76;
            }
        } else {
            logits[2] += -76;
        }
    } else {
        if (x[0] <= 738) {
            logits[2] += 86;
        } else {
            logits[2] += 86;
        }
    }
    /* Tree 15 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -76;
            } else {
                logits[2] += -76;
            }
        } else {
            logits[2] += -76;
        }
    } else {
        logits[2] += 84;
    }
    /* Tree 16 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -76;
            } else {
                logits[2] += -76;
            }
        } else {
            logits[2] += -76;
        }
    } else {
        logits[2] += 82;
    }
    /* Tree 17 for class 2 */
    if (x[9] <= 701) {
        if (x[10] <= 408) {
            if (x[8] <= 1275) {
                logits[2] += -75;
            } else {
                logits[2] += -76;
            }
        } else {
            logits[2] += -76;
        }
    } else {
        logits[2] += 81;
    }
    /* Tree 18 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -75;
            } else {
                logits[2] += -76;
            }
        } else {
            logits[2] += -76;
        }
    } else {
        logits[2] += 80;
    }
    /* Tree 19 for class 2 */
    if (x[9] <= 701) {
        if (x[1] <= 819) {
            if (x[8] <= 1275) {
                logits[2] += -75;
            } else {
                logits[2] += -75;
            }
        } else {
            logits[2] += -75;
        }
    } else {
        logits[2] += 79;
    }
    /* Tree 20 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -75;
            } else {
                logits[2] += -75;
            }
        } else {
            logits[2] += -75;
        }
    } else {
        logits[2] += 79;
    }
    /* Tree 21 for class 2 */
    if (x[9] <= 701) {
        if (x[10] <= 408) {
            if (x[8] <= 1275) {
                logits[2] += -75;
            } else {
                logits[2] += -75;
            }
        } else {
            logits[2] += -75;
        }
    } else {
        logits[2] += 78;
    }
    /* Tree 22 for class 2 */
    if (x[9] <= 701) {
        if (x[1] <= 819) {
            if (x[8] <= 1275) {
                logits[2] += -75;
            } else {
                logits[2] += -75;
            }
        } else {
            logits[2] += -75;
        }
    } else {
        logits[2] += 78;
    }
    /* Tree 23 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -75;
            } else {
                logits[2] += -75;
            }
        } else {
            logits[2] += -75;
        }
    } else {
        logits[2] += 77;
    }
    /* Tree 24 for class 2 */
    if (x[9] <= 701) {
        if (x[10] <= 408) {
            if (x[8] <= 1275) {
                logits[2] += -75;
            } else {
                logits[2] += -75;
            }
        } else {
            logits[2] += -75;
        }
    } else {
        logits[2] += 77;
    }
    /* Tree 25 for class 2 */
    if (x[9] <= 701) {
        if (x[2] <= 300) {
            if (x[8] <= 1275) {
                logits[2] += -75;
            } else {
                logits[2] += -75;
            }
        } else {
            logits[2] += -75;
        }
    } else {
        logits[2] += 76;
    }
    /* Tree 0 for class 3 */
    if (x[8] <= 1275) {
        logits[3] += -84;
    } else {
        if (x[4] <= 1540) {
            logits[3] += 673;
        } else {
            logits[3] += 673;
        }
    }
    /* Tree 1 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -83;
        } else {
            if (x[1] <= 819) {
                logits[3] += -83;
            } else {
                logits[3] += -83;
            }
        }
    } else {
        logits[3] += 335;
    }
    /* Tree 2 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            if (x[7] <= 176) {
                logits[3] += -82;
            } else {
                logits[3] += -82;
            }
        } else {
            if (x[1] <= 819) {
                logits[3] += -83;
            } else {
                logits[3] += -83;
            }
        }
    } else {
        logits[3] += 238;
    }
    /* Tree 3 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            if (x[6] <= 172) {
                logits[3] += -81;
            } else {
                logits[3] += -81;
            }
        } else {
            if (x[1] <= 819) {
                logits[3] += -82;
            } else {
                logits[3] += -82;
            }
        }
    } else {
        logits[3] += 189;
    }
    /* Tree 4 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -80;
        } else {
            if (x[2] <= 225) {
                logits[3] += -81;
            } else {
                logits[3] += -81;
            }
        }
    } else {
        if (x[12] <= 750) {
            logits[3] += 160;
        } else {
            if (x[11] <= 6) {
                logits[3] += 160;
            } else {
                logits[3] += 160;
            }
        }
    }
    /* Tree 5 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -79;
        } else {
            if (x[1] <= 819) {
                logits[3] += -80;
            } else {
                logits[3] += -80;
            }
        }
    } else {
        if (x[6] <= 675) {
            if (x[4] <= 1570) {
                logits[3] += 140;
            } else {
                logits[3] += 140;
            }
        } else {
            logits[3] += 140;
        }
    }
    /* Tree 6 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            if (x[0] <= 0) {
                logits[3] += -78;
            } else {
                logits[3] += -78;
            }
        } else {
            if (x[2] <= 225) {
                logits[3] += -80;
            } else {
                logits[3] += -80;
            }
        }
    } else {
        if (x[8] <= 1789) {
            logits[3] += 126;
        } else {
            if (x[0] <= 16) {
                logits[3] += 126;
            } else {
                logits[3] += 126;
            }
        }
    }
    /* Tree 7 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -78;
        } else {
            if (x[9] <= 701) {
                logits[3] += -79;
            } else {
                logits[3] += -79;
            }
        }
    } else {
        logits[3] += 116;
    }
    /* Tree 8 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -77;
        } else {
            if (x[1] <= 819) {
                logits[3] += -78;
            } else {
                logits[3] += -78;
            }
        }
    } else {
        if (x[4] <= 1631) {
            logits[3] += 108;
        } else {
            if (x[0] <= 17) {
                logits[3] += 108;
            } else {
                logits[3] += 108;
            }
        }
    }
    /* Tree 9 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -77;
        } else {
            if (x[9] <= 701) {
                logits[3] += -78;
            } else {
                logits[3] += -78;
            }
        }
    } else {
        logits[3] += 102;
    }
    /* Tree 10 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -77;
        } else {
            if (x[9] <= 701) {
                logits[3] += -77;
            } else {
                logits[3] += -77;
            }
        }
    } else {
        logits[3] += 98;
    }
    /* Tree 11 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -76;
        } else {
            if (x[9] <= 701) {
                logits[3] += -77;
            } else {
                logits[3] += -77;
            }
        }
    } else {
        logits[3] += 94;
    }
    /* Tree 12 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -76;
        } else {
            if (x[2] <= 225) {
                logits[3] += -77;
            } else {
                logits[3] += -77;
            }
        }
    } else {
        if (x[0] <= 17) {
            logits[3] += 91;
        } else {
            logits[3] += 91;
        }
    }
    /* Tree 13 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -76;
        } else {
            if (x[9] <= 701) {
                logits[3] += -76;
            } else {
                logits[3] += -76;
            }
        }
    } else {
        logits[3] += 88;
    }
    /* Tree 14 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -76;
        } else {
            if (x[2] <= 225) {
                logits[3] += -76;
            } else {
                logits[3] += -76;
            }
        }
    } else {
        if (x[8] <= 1826) {
            logits[3] += 86;
        } else {
            logits[3] += 86;
        }
    }
    /* Tree 15 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -76;
        } else {
            if (x[1] <= 819) {
                logits[3] += -76;
            } else {
                logits[3] += -76;
            }
        }
    } else {
        if (x[7] <= 124) {
            logits[3] += 84;
        } else {
            logits[3] += 84;
        }
    }
    /* Tree 16 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -75;
        } else {
            if (x[9] <= 701) {
                logits[3] += -76;
            } else {
                logits[3] += -76;
            }
        }
    } else {
        logits[3] += 83;
    }
    /* Tree 17 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -75;
        } else {
            if (x[9] <= 701) {
                logits[3] += -76;
            } else {
                logits[3] += -76;
            }
        }
    } else {
        if (x[1] <= 277) {
            logits[3] += 81;
        } else {
            if (x[4] <= 1541) {
                logits[3] += 81;
            } else {
                logits[3] += 81;
            }
        }
    }
    /* Tree 18 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -75;
        } else {
            if (x[9] <= 701) {
                logits[3] += -75;
            } else {
                logits[3] += -75;
            }
        }
    } else {
        logits[3] += 80;
    }
    /* Tree 19 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -75;
        } else {
            if (x[9] <= 701) {
                logits[3] += -75;
            } else {
                logits[3] += -75;
            }
        }
    } else {
        logits[3] += 80;
    }
    /* Tree 20 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -75;
        } else {
            if (x[9] <= 701) {
                logits[3] += -75;
            } else {
                logits[3] += -75;
            }
        }
    } else {
        logits[3] += 79;
    }
    /* Tree 21 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -75;
        } else {
            if (x[1] <= 819) {
                logits[3] += -75;
            } else {
                logits[3] += -75;
            }
        }
    } else {
        logits[3] += 78;
    }
    /* Tree 22 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -75;
        } else {
            if (x[1] <= 819) {
                logits[3] += -75;
            } else {
                logits[3] += -75;
            }
        }
    } else {
        logits[3] += 78;
    }
    /* Tree 23 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -75;
        } else {
            if (x[9] <= 701) {
                logits[3] += -75;
            } else {
                logits[3] += -75;
            }
        }
    } else {
        logits[3] += 77;
    }
    /* Tree 24 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -75;
        } else {
            if (x[1] <= 819) {
                logits[3] += -75;
            } else {
                logits[3] += -75;
            }
        }
    } else {
        logits[3] += 77;
    }
    /* Tree 25 for class 3 */
    if (x[8] <= 1275) {
        if (x[10] <= 154) {
            logits[3] += -75;
        } else {
            if (x[9] <= 701) {
                logits[3] += -75;
            } else {
                logits[3] += -75;
            }
        }
    } else {
        logits[3] += 77;
    }

    /* Argmax over logits */
    gint max_logit = logits[0];
    gint best_class = 0;
    for (gint c = 1; c < 4; c++) {
        if (logits[c] > max_logit) {
            max_logit = logits[c];
            best_class = c;
        }
    }
    return best_class;
}

#endif /* FS_ML_MODEL_H */

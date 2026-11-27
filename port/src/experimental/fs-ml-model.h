/*--[ fs-ml-model.h ]----------------------------------------------------
 * Neural Sentinel: Auto-generated INT8 GBDT Model Header
 * Test F1 Score: 1.0000 (Trained offline on synthetic host behavior windows)
 *--------------------------------------------------------------------*/
#ifndef FS_ML_MODEL_H
#define FS_ML_MODEL_H

#include <glib.h>

#define FS_ML_N_ESTIMATORS 16
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
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[0] += 114;
        } else {
            logits[0] += -217;
        }
    } else {
        if (x[5] <= 136) {
            logits[0] += -217;
        } else {
            logits[0] += -217;
        }
    }
    /* Tree 1 for class 0 */
    if (x[2] <= 325) {
        logits[0] += -88;
    } else {
        logits[0] += 490;
    }
    /* Tree 2 for class 0 */
    if (x[9] <= 829) {
        logits[0] += -82;
    } else {
        if (x[7] <= 92) {
            logits[0] += 804;
        } else {
            if (x[8] <= 2) {
                logits[0] += 804;
            } else {
                logits[0] += 804;
            }
        }
    }
    /* Tree 3 for class 0 */
    if (x[8] <= 1339) {
        logits[0] += -83;
    } else {
        logits[0] += 761;
    }
    /* Tree 0 for class 1 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[1] += 107;
        } else {
            if (x[6] <= 334) {
                logits[1] += -165;
            } else {
                logits[1] += -165;
            }
        }
    } else {
        if (x[1] <= 812) {
            if (x[10] <= 270) {
                logits[1] += -165;
            } else {
                logits[1] += -165;
            }
        } else {
            logits[1] += -167;
        }
    }
    /* Tree 1 for class 1 */
    if (x[2] <= 325) {
        if (x[8] <= 1339) {
            if (x[10] <= 153) {
                logits[1] += -86;
            } else {
                logits[1] += -87;
            }
        } else {
            logits[1] += -87;
        }
    } else {
        logits[1] += 286;
    }
    /* Tree 2 for class 1 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[1] += -81;
            } else {
                logits[1] += -82;
            }
        } else {
            if (x[10] <= 9) {
                logits[1] += -81;
            } else {
                logits[1] += -82;
            }
        }
    } else {
        if (x[1] <= 278) {
            logits[1] += 347;
        } else {
            logits[1] += 347;
        }
    }
    /* Tree 3 for class 1 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            if (x[8] <= 27) {
                logits[1] += -82;
            } else {
                logits[1] += -82;
            }
        } else {
            if (x[9] <= 829) {
                logits[1] += -82;
            } else {
                logits[1] += -82;
            }
        }
    } else {
        if (x[12] <= 450) {
            if (x[5] <= 159) {
                logits[1] += 342;
            } else {
                logits[1] += 342;
            }
        } else {
            logits[1] += 342;
        }
    }
    /* Tree 0 for class 2 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            if (x[4] <= 2123) {
                logits[2] += 101;
            } else {
                logits[2] += 101;
            }
        } else {
            if (x[1] <= 624) {
                logits[2] += -141;
            } else {
                logits[2] += -141;
            }
        }
    } else {
        if (x[2] <= 212) {
            logits[2] += -141;
        } else {
            logits[2] += -142;
        }
    }
    /* Tree 1 for class 2 */
    if (x[1] <= 812) {
        if (x[8] <= 1339) {
            if (x[10] <= 153) {
                logits[2] += -84;
            } else {
                logits[2] += -86;
            }
        } else {
            if (x[1] <= 624) {
                logits[2] += -86;
            } else {
                logits[2] += -86;
            }
        }
    } else {
        if (x[4] <= 1562) {
            if (x[0] <= 859) {
                logits[2] += 212;
            } else {
                logits[2] += 212;
            }
        } else {
            logits[2] += 212;
        }
    }
    /* Tree 2 for class 2 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[2] += -80;
            } else {
                logits[2] += -81;
            }
        } else {
            if (x[10] <= 9) {
                logits[2] += -80;
            } else {
                logits[2] += -81;
            }
        }
    } else {
        logits[2] += 242;
    }
    /* Tree 3 for class 2 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            if (x[9] <= 0) {
                logits[2] += -81;
            } else {
                logits[2] += -81;
            }
        } else {
            if (x[1] <= 812) {
                logits[2] += -82;
            } else {
                logits[2] += -82;
            }
        }
    } else {
        if (x[1] <= 624) {
            if (x[1] <= 275) {
                logits[2] += 240;
            } else {
                logits[2] += 240;
            }
        } else {
            if (x[8] <= 1999) {
                logits[2] += 240;
            } else {
                logits[2] += 240;
            }
        }
    }
    /* Tree 0 for class 3 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            if (x[8] <= 25) {
                logits[3] += 97;
            } else {
                logits[3] += 97;
            }
        } else {
            if (x[1] <= 624) {
                logits[3] += -126;
            } else {
                logits[3] += -126;
            }
        }
    } else {
        if (x[9] <= 829) {
            if (x[7] <= 274) {
                logits[3] += -126;
            } else {
                logits[3] += -126;
            }
        } else {
            logits[3] += -126;
        }
    }
    /* Tree 1 for class 3 */
    if (x[2] <= 325) {
        if (x[8] <= 1339) {
            if (x[9] <= 829) {
                logits[3] += -83;
            } else {
                logits[3] += -85;
            }
        } else {
            if (x[1] <= 624) {
                logits[3] += -85;
            } else {
                logits[3] += -85;
            }
        }
    } else {
        logits[3] += 172;
    }
    /* Tree 2 for class 3 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[3] += -79;
            } else {
                logits[3] += -81;
            }
        } else {
            if (x[10] <= 9) {
                logits[3] += -79;
            } else {
                logits[3] += -81;
            }
        }
    } else {
        logits[3] += 191;
    }
    /* Tree 3 for class 3 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[3] += -80;
        } else {
            if (x[2] <= 212) {
                logits[3] += -81;
            } else {
                logits[3] += -81;
            }
        }
    } else {
        if (x[1] <= 624) {
            logits[3] += 189;
        } else {
            logits[3] += 189;
        }
    }
    /* Tree 0 for class 4 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[4] += 93;
        } else {
            if (x[1] <= 624) {
                logits[4] += -115;
            } else {
                logits[4] += -115;
            }
        }
    } else {
        if (x[9] <= 829) {
            if (x[7] <= 159) {
                logits[4] += -115;
            } else {
                logits[4] += -115;
            }
        } else {
            if (x[9] <= 1622) {
                logits[4] += -115;
            } else {
                logits[4] += -115;
            }
        }
    }
    /* Tree 1 for class 4 */
    if (x[1] <= 812) {
        if (x[8] <= 1339) {
            if (x[10] <= 153) {
                logits[4] += -82;
            } else {
                logits[4] += -84;
            }
        } else {
            if (x[1] <= 624) {
                logits[4] += -84;
            } else {
                logits[4] += -84;
            }
        }
    } else {
        if (x[8] <= 27) {
            logits[4] += 148;
        } else {
            if (x[5] <= 337) {
                logits[4] += 148;
            } else {
                logits[4] += 148;
            }
        }
    }
    /* Tree 2 for class 4 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[4] += -79;
            } else {
                logits[4] += -80;
            }
        } else {
            if (x[10] <= 9) {
                logits[4] += -79;
            } else {
                logits[4] += -80;
            }
        }
    } else {
        if (x[4] <= 1540) {
            logits[4] += 160;
        } else {
            logits[4] += 160;
        }
    }
    /* Tree 3 for class 4 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[4] += -79;
        } else {
            if (x[2] <= 212) {
                logits[4] += -80;
            } else {
                logits[4] += -80;
            }
        }
    } else {
        if (x[1] <= 624) {
            if (x[7] <= 84) {
                logits[4] += 159;
            } else {
                logits[4] += 159;
            }
        } else {
            if (x[6] <= 629) {
                logits[4] += 159;
            } else {
                logits[4] += 159;
            }
        }
    }
    /* Tree 0 for class 5 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[5] += 90;
        } else {
            if (x[1] <= 624) {
                logits[5] += -107;
            } else {
                logits[5] += -107;
            }
        }
    } else {
        if (x[1] <= 812) {
            logits[5] += -107;
        } else {
            logits[5] += -107;
        }
    }
    /* Tree 1 for class 5 */
    if (x[1] <= 812) {
        if (x[8] <= 1339) {
            if (x[10] <= 153) {
                logits[5] += -81;
            } else {
                logits[5] += -83;
            }
        } else {
            if (x[1] <= 624) {
                logits[5] += -83;
            } else {
                logits[5] += -83;
            }
        }
    } else {
        logits[5] += 131;
    }
    /* Tree 2 for class 5 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[5] += -78;
            } else {
                logits[5] += -79;
            }
        } else {
            if (x[10] <= 9) {
                logits[5] += -78;
            } else {
                logits[5] += -79;
            }
        }
    } else {
        logits[5] += 140;
    }
    /* Tree 3 for class 5 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[5] += -78;
        } else {
            if (x[2] <= 212) {
                logits[5] += -80;
            } else {
                logits[5] += -80;
            }
        }
    } else {
        if (x[1] <= 624) {
            if (x[8] <= 1915) {
                logits[5] += 140;
            } else {
                logits[5] += 140;
            }
        } else {
            if (x[7] <= 653) {
                logits[5] += 140;
            } else {
                logits[5] += 140;
            }
        }
    }
    /* Tree 0 for class 6 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[6] += 88;
        } else {
            if (x[1] <= 624) {
                logits[6] += -101;
            } else {
                logits[6] += -101;
            }
        }
    } else {
        if (x[2] <= 212) {
            logits[6] += -101;
        } else {
            logits[6] += -101;
        }
    }
    /* Tree 1 for class 6 */
    if (x[2] <= 325) {
        if (x[8] <= 1339) {
            if (x[10] <= 153) {
                logits[6] += -80;
            } else {
                logits[6] += -82;
            }
        } else {
            if (x[1] <= 624) {
                logits[6] += -82;
            } else {
                logits[6] += -82;
            }
        }
    } else {
        logits[6] += 120;
    }
    /* Tree 2 for class 6 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[6] += -78;
            } else {
                logits[6] += -79;
            }
        } else {
            if (x[10] <= 9) {
                logits[6] += -78;
            } else {
                logits[6] += -79;
            }
        }
    } else {
        logits[6] += 126;
    }
    /* Tree 3 for class 6 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            if (x[0] <= 0) {
                logits[6] += -78;
            } else {
                logits[6] += -78;
            }
        } else {
            if (x[1] <= 812) {
                logits[6] += -79;
            } else {
                logits[6] += -79;
            }
        }
    } else {
        if (x[1] <= 624) {
            if (x[9] <= 2) {
                logits[6] += 126;
            } else {
                logits[6] += 126;
            }
        } else {
            if (x[10] <= 25) {
                logits[6] += 126;
            } else {
                logits[6] += 126;
            }
        }
    }
    /* Tree 0 for class 7 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[7] += 86;
        } else {
            if (x[1] <= 624) {
                logits[7] += -97;
            } else {
                logits[7] += -97;
            }
        }
    } else {
        if (x[2] <= 212) {
            if (x[5] <= 142) {
                logits[7] += -97;
            } else {
                logits[7] += -97;
            }
        } else {
            if (x[8] <= 18) {
                logits[7] += -97;
            } else {
                logits[7] += -97;
            }
        }
    }
    /* Tree 1 for class 7 */
    if (x[1] <= 812) {
        if (x[8] <= 1339) {
            if (x[9] <= 829) {
                logits[7] += -79;
            } else {
                logits[7] += -81;
            }
        } else {
            if (x[1] <= 624) {
                logits[7] += -81;
            } else {
                logits[7] += -81;
            }
        }
    } else {
        if (x[10] <= 770) {
            logits[7] += 111;
        } else {
            if (x[7] <= 74) {
                logits[7] += 111;
            } else {
                logits[7] += 111;
            }
        }
    }
    /* Tree 2 for class 7 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[7] += -77;
            } else {
                logits[7] += -78;
            }
        } else {
            if (x[10] <= 9) {
                logits[7] += -77;
            } else {
                logits[7] += -78;
            }
        }
    } else {
        if (x[9] <= 1536) {
            logits[7] += 116;
        } else {
            logits[7] += 116;
        }
    }
    /* Tree 3 for class 7 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            if (x[8] <= 42) {
                logits[7] += -77;
            } else {
                logits[7] += -77;
            }
        } else {
            if (x[9] <= 829) {
                logits[7] += -79;
            } else {
                logits[7] += -79;
            }
        }
    } else {
        if (x[1] <= 624) {
            logits[7] += 116;
        } else {
            if (x[5] <= 773) {
                logits[7] += 116;
            } else {
                logits[7] += 116;
            }
        }
    }
    /* Tree 0 for class 8 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            if (x[5] <= 128) {
                logits[8] += 84;
            } else {
                logits[8] += 84;
            }
        } else {
            if (x[1] <= 624) {
                logits[8] += -93;
            } else {
                logits[8] += -93;
            }
        }
    } else {
        if (x[9] <= 829) {
            logits[8] += -93;
        } else {
            if (x[4] <= 1560) {
                logits[8] += -93;
            } else {
                logits[8] += -93;
            }
        }
    }
    /* Tree 1 for class 8 */
    if (x[1] <= 812) {
        if (x[8] <= 1339) {
            if (x[9] <= 829) {
                logits[8] += -78;
            } else {
                logits[8] += -80;
            }
        } else {
            if (x[1] <= 624) {
                logits[8] += -80;
            } else {
                logits[8] += -80;
            }
        }
    } else {
        if (x[2] <= 387) {
            logits[8] += 104;
        } else {
            logits[8] += 104;
        }
    }
    /* Tree 2 for class 8 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[8] += -77;
            } else {
                logits[8] += -78;
            }
        } else {
            if (x[10] <= 9) {
                logits[8] += -77;
            } else {
                logits[8] += -78;
            }
        }
    } else {
        if (x[6] <= 151) {
            logits[8] += 108;
        } else {
            if (x[5] <= 222) {
                logits[8] += 108;
            } else {
                logits[8] += 108;
            }
        }
    }
    /* Tree 3 for class 8 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[8] += -77;
        } else {
            if (x[9] <= 829) {
                logits[8] += -78;
            } else {
                logits[8] += -78;
            }
        }
    } else {
        if (x[1] <= 624) {
            logits[8] += 108;
        } else {
            if (x[1] <= 624) {
                logits[8] += 108;
            } else {
                logits[8] += 108;
            }
        }
    }
    /* Tree 0 for class 9 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[9] += 83;
        } else {
            if (x[1] <= 624) {
                logits[9] += -90;
            } else {
                logits[9] += -90;
            }
        }
    } else {
        if (x[2] <= 212) {
            logits[9] += -90;
        } else {
            logits[9] += -90;
        }
    }
    /* Tree 1 for class 9 */
    if (x[1] <= 812) {
        if (x[8] <= 1339) {
            if (x[10] <= 153) {
                logits[9] += -78;
            } else {
                logits[9] += -79;
            }
        } else {
            if (x[1] <= 624) {
                logits[9] += -79;
            } else {
                logits[9] += -79;
            }
        }
    } else {
        if (x[9] <= 2) {
            logits[9] += 99;
        } else {
            if (x[8] <= 10) {
                logits[9] += 99;
            } else {
                logits[9] += 99;
            }
        }
    }
    /* Tree 2 for class 9 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[9] += -77;
            } else {
                logits[9] += -77;
            }
        } else {
            if (x[10] <= 9) {
                logits[9] += -77;
            } else {
                logits[9] += -77;
            }
        }
    } else {
        logits[9] += 102;
    }
    /* Tree 3 for class 9 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[9] += -77;
        } else {
            if (x[9] <= 829) {
                logits[9] += -78;
            } else {
                logits[9] += -78;
            }
        }
    } else {
        if (x[1] <= 624) {
            logits[9] += 102;
        } else {
            if (x[7] <= 653) {
                logits[9] += 102;
            } else {
                logits[9] += 102;
            }
        }
    }
    /* Tree 0 for class 10 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[10] += 81;
        } else {
            if (x[1] <= 624) {
                logits[10] += -87;
            } else {
                logits[10] += -87;
            }
        }
    } else {
        if (x[2] <= 212) {
            logits[10] += -87;
        } else {
            if (x[5] <= 129) {
                logits[10] += -87;
            } else {
                logits[10] += -87;
            }
        }
    }
    /* Tree 1 for class 10 */
    if (x[2] <= 325) {
        if (x[8] <= 1339) {
            if (x[10] <= 153) {
                logits[10] += -77;
            } else {
                logits[10] += -79;
            }
        } else {
            if (x[1] <= 624) {
                logits[10] += -79;
            } else {
                logits[10] += -79;
            }
        }
    } else {
        logits[10] += 95;
    }
    /* Tree 2 for class 10 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[10] += -76;
            } else {
                logits[10] += -77;
            }
        } else {
            if (x[10] <= 9) {
                logits[10] += -76;
            } else {
                logits[10] += -77;
            }
        }
    } else {
        if (x[8] <= 1) {
            logits[10] += 97;
        } else {
            logits[10] += 97;
        }
    }
    /* Tree 3 for class 10 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[10] += -76;
        } else {
            if (x[1] <= 812) {
                logits[10] += -77;
            } else {
                logits[10] += -77;
            }
        }
    } else {
        if (x[1] <= 624) {
            if (x[0] <= 20) {
                logits[10] += 97;
            } else {
                logits[10] += 97;
            }
        } else {
            if (x[6] <= 629) {
                logits[10] += 97;
            } else {
                logits[10] += 97;
            }
        }
    }
    /* Tree 0 for class 11 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[11] += 80;
        } else {
            if (x[1] <= 624) {
                logits[11] += -85;
            } else {
                logits[11] += -85;
            }
        }
    } else {
        if (x[2] <= 212) {
            logits[11] += -85;
        } else {
            if (x[6] <= 564) {
                logits[11] += -85;
            } else {
                logits[11] += -85;
            }
        }
    }
    /* Tree 1 for class 11 */
    if (x[2] <= 325) {
        if (x[8] <= 1339) {
            if (x[10] <= 153) {
                logits[11] += -77;
            } else {
                logits[11] += -78;
            }
        } else {
            if (x[1] <= 624) {
                logits[11] += -78;
            } else {
                logits[11] += -78;
            }
        }
    } else {
        logits[11] += 92;
    }
    /* Tree 2 for class 11 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[11] += -76;
            } else {
                logits[11] += -77;
            }
        } else {
            if (x[10] <= 9) {
                logits[11] += -76;
            } else {
                logits[11] += -77;
            }
        }
    } else {
        if (x[5] <= 208) {
            logits[11] += 94;
        } else {
            if (x[7] <= 111) {
                logits[11] += 94;
            } else {
                logits[11] += 94;
            }
        }
    }
    /* Tree 3 for class 11 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[11] += -76;
        } else {
            if (x[9] <= 829) {
                logits[11] += -77;
            } else {
                logits[11] += -77;
            }
        }
    } else {
        if (x[1] <= 624) {
            if (x[10] <= 0) {
                logits[11] += 93;
            } else {
                logits[11] += 93;
            }
        } else {
            if (x[7] <= 653) {
                logits[11] += 93;
            } else {
                logits[11] += 93;
            }
        }
    }
    /* Tree 0 for class 12 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            if (x[10] <= 0) {
                logits[12] += 79;
            } else {
                logits[12] += 79;
            }
        } else {
            if (x[1] <= 624) {
                logits[12] += -84;
            } else {
                logits[12] += -84;
            }
        }
    } else {
        if (x[9] <= 829) {
            logits[12] += -84;
        } else {
            if (x[1] <= 278) {
                logits[12] += -84;
            } else {
                logits[12] += -84;
            }
        }
    }
    /* Tree 1 for class 12 */
    if (x[1] <= 812) {
        if (x[8] <= 1339) {
            if (x[9] <= 829) {
                logits[12] += -77;
            } else {
                logits[12] += -78;
            }
        } else {
            if (x[1] <= 624) {
                logits[12] += -78;
            } else {
                logits[12] += -78;
            }
        }
    } else {
        logits[12] += 89;
    }
    /* Tree 2 for class 12 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[12] += -76;
            } else {
                logits[12] += -76;
            }
        } else {
            if (x[10] <= 9) {
                logits[12] += -76;
            } else {
                logits[12] += -76;
            }
        }
    } else {
        logits[12] += 91;
    }
    /* Tree 3 for class 12 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[12] += -76;
        } else {
            if (x[1] <= 812) {
                logits[12] += -77;
            } else {
                logits[12] += -77;
            }
        }
    } else {
        if (x[1] <= 624) {
            if (x[1] <= 315) {
                logits[12] += 90;
            } else {
                logits[12] += 90;
            }
        } else {
            logits[12] += 90;
        }
    }
    /* Tree 0 for class 13 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[13] += 79;
        } else {
            if (x[1] <= 624) {
                logits[13] += -82;
            } else {
                logits[13] += -82;
            }
        }
    } else {
        if (x[1] <= 812) {
            logits[13] += -82;
        } else {
            logits[13] += -82;
        }
    }
    /* Tree 1 for class 13 */
    if (x[1] <= 812) {
        if (x[8] <= 1339) {
            if (x[9] <= 829) {
                logits[13] += -76;
            } else {
                logits[13] += -77;
            }
        } else {
            if (x[1] <= 624) {
                logits[13] += -77;
            } else {
                logits[13] += -77;
            }
        }
    } else {
        logits[13] += 87;
    }
    /* Tree 2 for class 13 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[13] += -76;
            } else {
                logits[13] += -76;
            }
        } else {
            if (x[10] <= 9) {
                logits[13] += -76;
            } else {
                logits[13] += -76;
            }
        }
    } else {
        if (x[5] <= 131) {
            logits[13] += 88;
        } else {
            if (x[4] <= 1536) {
                logits[13] += 88;
            } else {
                logits[13] += 88;
            }
        }
    }
    /* Tree 3 for class 13 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[13] += -76;
        } else {
            if (x[9] <= 829) {
                logits[13] += -76;
            } else {
                logits[13] += -76;
            }
        }
    } else {
        if (x[1] <= 624) {
            if (x[9] <= 4) {
                logits[13] += 88;
            } else {
                logits[13] += 88;
            }
        } else {
            logits[13] += 88;
        }
    }
    /* Tree 0 for class 14 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[14] += 78;
        } else {
            if (x[1] <= 624) {
                logits[14] += -81;
            } else {
                logits[14] += -81;
            }
        }
    } else {
        if (x[9] <= 829) {
            logits[14] += -81;
        } else {
            if (x[5] <= 158) {
                logits[14] += -81;
            } else {
                logits[14] += -81;
            }
        }
    }
    /* Tree 1 for class 14 */
    if (x[1] <= 812) {
        if (x[8] <= 1339) {
            if (x[10] <= 153) {
                logits[14] += -76;
            } else {
                logits[14] += -77;
            }
        } else {
            if (x[1] <= 624) {
                logits[14] += -77;
            } else {
                logits[14] += -77;
            }
        }
    } else {
        logits[14] += 85;
    }
    /* Tree 2 for class 14 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[14] += -75;
            } else {
                logits[14] += -76;
            }
        } else {
            if (x[10] <= 9) {
                logits[14] += -75;
            } else {
                logits[14] += -76;
            }
        }
    } else {
        logits[14] += 86;
    }
    /* Tree 3 for class 14 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[14] += -76;
        } else {
            if (x[2] <= 212) {
                logits[14] += -76;
            } else {
                logits[14] += -76;
            }
        }
    } else {
        if (x[1] <= 624) {
            if (x[8] <= 1923) {
                logits[14] += 86;
            } else {
                logits[14] += 86;
            }
        } else {
            logits[14] += 86;
        }
    }
    /* Tree 0 for class 15 */
    if (x[10] <= 153) {
        if (x[8] <= 1339) {
            logits[15] += 78;
        } else {
            if (x[1] <= 624) {
                logits[15] += -80;
            } else {
                logits[15] += -80;
            }
        }
    } else {
        if (x[9] <= 829) {
            logits[15] += -80;
        } else {
            logits[15] += -80;
        }
    }
    /* Tree 1 for class 15 */
    if (x[2] <= 325) {
        if (x[8] <= 1339) {
            if (x[10] <= 153) {
                logits[15] += -76;
            } else {
                logits[15] += -76;
            }
        } else {
            if (x[1] <= 624) {
                logits[15] += -76;
            } else {
                logits[15] += -76;
            }
        }
    } else {
        logits[15] += 83;
    }
    /* Tree 2 for class 15 */
    if (x[9] <= 829) {
        if (x[1] <= 624) {
            if (x[8] <= 1339) {
                logits[15] += -75;
            } else {
                logits[15] += -76;
            }
        } else {
            if (x[10] <= 9) {
                logits[15] += -75;
            } else {
                logits[15] += -76;
            }
        }
    } else {
        logits[15] += 84;
    }
    /* Tree 3 for class 15 */
    if (x[8] <= 1339) {
        if (x[10] <= 153) {
            logits[15] += -75;
        } else {
            if (x[9] <= 829) {
                logits[15] += -76;
            } else {
                logits[15] += -76;
            }
        }
    } else {
        if (x[1] <= 624) {
            logits[15] += 84;
        } else {
            logits[15] += 84;
        }
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

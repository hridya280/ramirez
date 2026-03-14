import numpy as np
import joblib
from tensorflow.keras.models import load_model

# ------------------------
# Load saved files
# ------------------------


ann_model = load_model("intrusion_ann_model.h5")

print("Models loaded successfully")


# ------------------------
# Sample input
# (change values according to your dataset)
# ------------------------

# ------------------------
# Sample input for ANN
# ------------------------

print("Model input shape:", ann_model.input_shape)

n = ann_model.input_shape[1]

sample = np.random.rand(1, n)

ann_pred_prob = ann_model.predict(sample)

ann_pred = (ann_pred_prob > 0.5).astype(int)

print("ANN Probability:", ann_pred_prob)
print("ANN Prediction:", ann_pred)


# ------------------------
# Linear model prediction
# ------------------------


# ------------------------
# Final decision
# ------------------------

if ann_pred[0][0] == 1:
    print("⚠ Intrusion Detected")
else:
    print("Normal Traffic")
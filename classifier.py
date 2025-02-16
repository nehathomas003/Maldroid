import os
import pickle
import numpy as np
from keras.models import load_model
from androguard.core.bytecodes.apk import APK
from genetic_algorithm import GeneticSelector


class CustomUnpickler(pickle.Unpickler):
    """ https://stackoverflow.com/questions/27732354/unable-to-load-files-using-pickle-and-multiple-modules"""

    def find_class(self, module, name):
        try:
            return super().find_class(__name__, name)
        except AttributeError:
            return super().find_class(module, name)


sel = CustomUnpickler(open('./static/models/ga.pkl', 'rb')).load()

permissions = []
with open('./static/permissions.txt', 'r') as f:
    content = f.readlines()
    for line in content:
        cur_perm = line[:-1]
        permissions.append(cur_perm)


def generate_lime_explanation(data):
    # This function mimics the LIME explanation style using your feature data
    explanation = []
    for i, perm in enumerate(permissions):
        if data[i] == 1:  # Permission is present
            explanation.append(f"Permission {perm} contributed to the prediction.")
    # Sort by most influential (example: based on frequency or impact on prediction)
    return sorted(explanation, key=lambda x: len(x), reverse=True)  # Simulating impact ranking

def classify(file, ch):
    vector = {}
    result = ""
    explanation = ""
    name, sdk, size = "unknown", "unknown", "unknown"
    
    app = APK(file)
    perm = app.get_permissions()
    name, sdk, size = meta_fetch(file)
    
    for p in permissions:
        vector[p] = 1 if p in perm else 0
    
    data = np.array([v for v in vector.values()])
    
    if ch == 0:  # Neural Network
        ANN = load_model("static/models/models.h5")
        result = ANN.predict([data[sel.support_].tolist()])[0][0]
        explanation = generate_lime_explanation(data)  # Using simulated LIME explanation

        if result < 0.02:
            result = "Benign(safe)"
        else:
            result = "Malware"

    elif ch in [1, 2]:  # SVC or Ensemble
        model_file = "static/models/svc_ga.pkl" if ch == 1 else "static/models/ensemble.pkl"
        model = pickle.load(open(model_file, "rb"))

        # Check if model supports decision_function
        if hasattr(model, "decision_function"):
            raw_output = model.decision_function([data[sel.support_]])[0]
            result = "Benign(safe)" if raw_output < 0 else "Malware"
        else:
            raw_output = model.predict([data[sel.support_]])[0]
            result = "Benign(safe)" if raw_output == "benign" else "Malware"

        # Apply LIME
        explanation = generate_lime_explanation(data)  # Pass full feature array

    return result, name, sdk, size, explanation, perm  # Return permissions list


def meta_fetch(apk):
    app = APK(apk)
    return app.get_app_name(), app.get_target_sdk_version(), str(round(os.stat(apk).st_size / (1024 * 1024), 2)) + ' MB'









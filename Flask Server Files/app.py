from flask import Flask, render_template, jsonify, request
import json
import os
import numpy as np
import joblib
import pandas as pd
from tensorflow.keras.models import load_model
 
app = Flask(__name__)
 
base_dir = os.path.join(os.path.expanduser('~'), '', '') #REMOVED - ADD YOUR OWN BASE DIR TO THE FOLDER HERE.
 
model = load_model(os.path.join(base_dir, 'flaskmodel2.keras')) #flaskmodel.keras \ flaskmodel2.keras               Version 2 = no infiltration.
scaler = joblib.load(os.path.join(base_dir, 'scaler_flask2.pkl')) #scaler_flask.pkl \ scaler_flask2.pkl
with open(os.path.join(base_dir, 'class_names_flask2.json'), 'r') as f: #class_names_flask.json \ class_names_flask2.json
    class_names = json.load(f) #opens the class names and parses it

features = [
    'Flow Duration', 'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Fwd Packets/s', 'Bwd Packets/s',
    'Packet Length Max', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'SYN Flag Count', 'URG Flag Count',
    'Avg Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size'
]

detected_flows = [] #stores the amount of detected flows

@app.route('/')
def index():
    return render_template('index.html')
 
@app.route('/predict', methods=['POST']) #defines what to do for post requests
def predict():
    global detected_flows #issues with variable persistence so made global
    flow = request.get_json()
    if not flow:
        return jsonify({'error': 'No data received'}), 400
 
    try:
        values = [flow.get(feat, 0) for feat in features] #for each feature, get its values from the flow, or 0 if missing.
        x_df = pd.DataFrame([values], columns=features) #creates a dataframe with the values and features.
        x_scaled = scaler.transform(x_df)#apply the scaler i used to train
        x = x_scaled.reshape(1, 1, len(features)) #reshape to what lstm wants
 
        pred = model.predict(x, verbose=0) #runs model
        class_idx = np.argmax(pred) #takes index of highest class
        confidence = float(np.max(pred)) * 100 #calculates confidence as percentage
        label = class_names[class_idx] #assigns label to its class label
 
        #dictionary to show the results
        result = {
            'src_ip': flow.get('src_ip', 'N/A'),
            'dst_ip': flow.get('dst_ip', 'N/A'),
            'prediction': label,
            'confidence': round(confidence, 2),
            'time': pd.Timestamp.now().strftime('%H:%M:%S')
        }
 
        detected_flows.append(result) #adds to counter
        detected_flows = detected_flows[-10000:] # only keeps top 10k
        
        print(f"[PREDICTION] {result['src_ip']} -> {result['dst_ip']} | {label} ({result['confidence']}%)")
        return jsonify(result), 200
 
    except Exception as e:
        print(f'[ERROR] {e}')
        return jsonify({'error': str(e)}), 500
 
@app.route('/get_flows')
def get_flows():
    return jsonify({'flows': detected_flows})
 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
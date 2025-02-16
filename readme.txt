What is maldroid: 
Maldroid is an APK malware detection application that leverages explainable AI to interpret and explain model findings. The application performs two types of malware analysis:

	Static Analysis: This analyzes the permissions requested by the uploaded APK file and classifies it as benign or malware using 	Support Vector Classifier (SVC), Neural Networks, and an Ensemble technique. These models have been trained on a permissions 	dataset sourced from Kaggle.

	Dynamic Analysis: The APK file is executed in an analytical sandbox to observe its runtime behavior and detect any malicious 	patterns.

By combining static and dynamic analysis, Maldroid provides a comprehensive evaluation of APK files while offering explainability for its classification decisions.



How to run Maldroid:

After opening it in IDE (Visual Studio code), open cmd.

In cmd create a virtual environment: 
>>python -m venv venv

Activate the environment:
>>venv\Scripts\activate

The Install all requirements to run the project:
>>pip install -r requirements.txt

After use deactivate the environment using the:
>>deactivate

Important points to note: 
scikit-learn==0.24.1
numpy==1.19.2


Dynamic Analysis Source:
https://github.com/cyph3rryx/Malware-Detection-System
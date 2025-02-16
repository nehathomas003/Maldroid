from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import time
import classifier
import Advance
from werkzeug.utils import secure_filename
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import subprocess
from Advance import set_directories, analyze_file

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './static/upload/'
app.config['SECRET_KEY'] = 'd3Y5d5nJkU6CdwY'

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Permission categories mapping
permission_categories = {
    'Location': {
        'android.permission.ACCESS_COARSE_LOCATION': 'Approximate location access',
        'android.permission.ACCESS_FINE_LOCATION': 'Precise location access'
    },
    'Storage': {
        'android.permission.READ_EXTERNAL_STORAGE': 'Read external storage',
        'android.permission.WRITE_EXTERNAL_STORAGE': 'Write to external storage',
        'android.permission.READ_MEDIA_AUDIO': 'Read audio files',
        'android.permission.READ_MEDIA_IMAGES': 'Read image files'
    },
    'Network': {
        'android.permission.ACCESS_NETWORK_STATE': 'Access network state',
        'android.permission.INTERNET': 'Full internet access',
        'android.permission.CHANGE_WIFI_MULTICAST_STATE': 'Change WiFi multicast settings',
        'android.permission.ACCESS_WIFI_STATE': 'Access WiFi state'
    },
    'Camera': {
        'android.permission.CAMERA': 'Use camera'
    },
    'Phone': {
        'android.permission.READ_PHONE_STATE': 'Read phone status and identity',
        'android.permission.CALL_PHONE': 'Make phone calls',
        'android.permission.USE_CREDENTIALS': 'Use account credentials'
    },
    'Bluetooth': {
        'android.permission.BLUETOOTH': 'Basic Bluetooth operations',
        'android.permission.BLUETOOTH_ADMIN': 'Manage Bluetooth settings',
        'android.permission.BLUETOOTH_SCAN': 'Scan for Bluetooth devices',
        'android.permission.BLUETOOTH_ADVERTISE': 'Advertise Bluetooth presence',
        'android.permission.BLUETOOTH_CONNECT': 'Connect to Bluetooth devices'
    },
    'Audio': {
        'android.permission.MODIFY_AUDIO_SETTINGS': 'Modify audio settings',
        'android.permission.RECORD_AUDIO': 'Record audio'
    },
    'Notifications': {
        'android.permission.POST_NOTIFICATIONS': 'Post notifications',
        'android.permission.VIBRATE': 'Control vibration'
    },
    'Foreground Services': {
        'android.permission.FOREGROUND_SERVICE': 'Run foreground services',
        'android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK': 'Foreground media playback',
        'android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE': 'Foreground connected device service',
        'android.permission.FOREGROUND_SERVICE_DATA_SYNC': 'Foreground data sync'
    },
    'Others': {
        'android.permission.SYSTEM_ALERT_WINDOW': 'Draw over other apps',
        'android.permission.NFC': 'Use NFC communication',
        'android.permission.WAKE_LOCK': 'Prevent device from sleeping',
        'com.spotify.music.permission.SECURED_BROADCAST': 'Spotify secured broadcast',
        'com.sony.snei.np.android.account.provider.permission.DUID_READ_PROVIDER': 'Sony NP account read provider',
        'com.android.vending.BILLING': 'In-app billing',
        'android.permission.BROADCAST_STICKY': 'Send sticky broadcasts',
        'com.spotify.music.permission.C2D_MESSAGE': 'Spotify cloud messaging',
        'com.spotify.music.permission.INTERNAL_BROADCAST': 'Spotify internal broadcast',
        'com.sec.android.app.clockpackage.permission.READ_ALARM': 'Read alarm data',
        'com.samsung.WATCH_APP_TYPE.Companion': 'Samsung watch app companion',
        'com.google.android.gms.permission.AD_ID': 'Google advertising ID access',
        'com.samsung.android.samsungaccount.permission.ACCOUNT_MANAGER': 'Samsung account management',
        'android.permission.RECEIVE_BOOT_COMPLETED': 'Start after boot',
        'com.android.launcher.permission.INSTALL_SHORTCUT': 'Install home screen shortcuts',
        'com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE': 'Install referrer service',
        'com.google.android.apps.meetings.permission.MEET_LIVE_SHARING': 'Google Meet live sharing',
        'android.permission.GET_ACCOUNTS': 'Access user accounts',
        'com.google.android.c2dm.permission.RECEIVE': 'Receive cloud messages',
        'com.spotify.music.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION': 'Spotify dynamic receiver',
        'com.samsung.android.rubin.context.permission.READ_CONTEXT_MANAGER': 'Samsung context manager access'
    }
}

def categorize_permissions(permissions):
    categorized_permissions = {category: [] for category in permission_categories}
    uncategorized = []

    for perm in permissions:
        found = False
        for category, perm_dict in permission_categories.items():
            if perm in perm_dict:
                categorized_permissions[category].append(perm_dict[perm])
                found = True
                break
        if not found:
            uncategorized.append(perm)

    if uncategorized:
        categorized_permissions['Uncategorized'] = uncategorized

    return categorized_permissions

def create_permission_plot(categorized_permissions):
    categories = list(categorized_permissions.keys())
    permission_counts = [len(perms) for perms in categorized_permissions.values()]

    if sum(permission_counts) == 0:
        return None, None  

    # Bar chart
    plt.figure(figsize=(10, 6))
    plt.bar(categories, permission_counts, color=['blue', 'green', 'red', 'orange', 'purple', 'yellow'])
    plt.title('Permission Categories Used by APK')
    plt.xlabel('Permission Categories')
    plt.ylabel('Number of Permissions')
    plt.xticks(rotation=45)
    bar_chart_path = 'static/images/permissions_bar_chart.png'
    plt.savefig(bar_chart_path)
    plt.close()

    # Pie chart
    plt.figure(figsize=(8, 8))
    plt.pie(permission_counts, labels=categories, autopct='%1.1f%%', startangle=90)
    plt.title('Permission Category Distribution')
    pie_chart_path = 'static/images/permissions_pie_chart.png'
    plt.savefig(pie_chart_path)
    plt.close()

    return bar_chart_path, pie_chart_path

@app.route("/", methods=["GET", "POST"])
def home():
    algorithms = {
        "Neural Network": "96.26%",
        "Support Vector Classifier": "97.12%",
        "Ensemble Model": "95.64%",
    }

    result, accuracy, name, sdk, size, extracted_permissions = "", "", "", "", "", []
    categorized_permissions = {}
    plot_url, pie_url = None, None
    analysis_result = None

    if request.method == "POST":
        malware_dir = request.form.get("malware_dir").strip()
        benign_dir = request.form.get("benign_dir").strip()
        dynamic_analysis_dir = request.form.get("dynamic_analysis_dir").strip()

        for directory in [malware_dir, benign_dir, dynamic_analysis_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)

        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)

        file = request.files["file"]
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)

        if file and file.filename.endswith(".apk"):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

            set_directories(malware_dir, benign_dir, dynamic_analysis_dir)
            analysis_result = analyze_file(file_path)

            algorithm = request.form["algorithm"]
            accuracy = algorithms[algorithm]
            model_index = {"Neural Network": 0, "Support Vector Classifier": 1, "Ensemble Model": 2}[algorithm]

            result, name, sdk, size, _, extracted_permissions = classifier.classify(file_path, model_index)

            categorized_permissions = categorize_permissions(extracted_permissions)
            plot_url, pie_url = create_permission_plot(categorized_permissions)

    timestamp = int(time.time())
    return render_template(
        "index.html",
        result=result,
        algorithms=algorithms.keys(),
        accuracy=accuracy,
        name=name,
        sdk=sdk,
        size=size,
        categorized_permissions=categorized_permissions,
        plot_url=f"{plot_url}?{timestamp}" if plot_url else None,
        pie_url=f"{pie_url}?{timestamp}" if pie_url else None,
        analysis_result=analysis_result,
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)

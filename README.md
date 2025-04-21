 project name :RANSOMWARE EARLY DETECTION & RESPONSE SYSTEM

Project id : 05


RANSOMWARE EARLY DETECTION AND RESPONSE SYSTEM

This project is a Streamlit-based application designed to detect and respond to ransomware activity in real-time. It monitors system processes, scans for suspicious files, and uses machine learning models to predict ransomware behavior. The application also provides ransomware prevention tips and fetches the latest ransomware-related news.

1) Features

1.Real-Time Monitoring: Monitors CPU, memory, and processes for suspicious activity.
2.Ransomware Detection: Uses machine learning models to detect ransomware based on system and file attributes.
3.File Scanning: Scans specified directories for ransomware-like files and removes them.
4.Network Activity Monitoring: Detects and blocks suspicious network connections.
5.Ransomware Prevention Tips: Provides actionable tips to prevent ransomware attacks.
6.News Integration: Fetches the latest ransomware-related news using the NewsAPI.

2) Prerequisites
Before running the application, ensure you have the following:
Python 3.7 or higher installed on your system.
Git installed (optional, for cloning the repository).

3) Setup Instructions

1. Clone the Repository
Clone this repository to your local machine using Git:
git clone https://github.com/your-username/ransomware-detection-system.git
cd ransomware-detection-system

2. Install Dependencies
Install the required Python libraries by running:
pip install -r requirements.txt

3. Download Pre-Trained Models
Ensure you have the following pre-trained machine learning models in the project directory:
ransomware_detection_model.pkl
ransomware_detection_model_v2.pkl
If you don't have these models, you can train them using your dataset and save them using joblib.

4. Set Up NewsAPI Key
To fetch ransomware-related news, you need a valid API key from NewsAPI. Replace the placeholder API key in the code with your own:
python
Copy
api_key = "your_newsapi_key_here"
Running the Application
Start the Streamlit application by running:
streamlit run app3.py
Open your web browser and navigate to the URL provided in the terminal (usually http://localhost:8501).

5. Use the application to:

1.Monitor system activity in real-time.
2.Detect and remove ransomware files.
3.Predict ransomware behavior using machine learning models.

View ransomware prevention tips and news.

4) Directory Structure

ransomware-detection-system/
├── app3.py                  # Main application script
├── requirements.txt         # List of dependencies
├── ransomware_detection_model.pkl      # Pre-trained model 1
├── ransomware_detection_model_v2.pkl   # Pre-trained model 2
├── README.md                # This file


5) Configuration
Directories to Scan
The application scans specific directories for ransomware-like files. You can modify the directories_to_scan list in the code to include your desired paths:


directories_to_scan = ["C:\\Users\\Public", "C:\\Windows\\Temp", "C:\\Users\\Public\\Test_Files"]
Blacklisted IPs
The application checks for connections to blacklisted IPs. You can update the BLACKLISTED_IPS list in the code:


BLACKLISTED_IPS = ["185.220.100.240", "185.220.101.7", ...]
Troubleshooting
Permission Errors: Ensure the application has the necessary permissions to access system resources and delete files.

Missing Models: If the pre-trained models are missing, the application will fail to make predictions. Train and save the models before running the app.

NewsAPI Errors: If the NewsAPI key is invalid or the API limit is exceeded, the news section will not work.

Contributing
Contributions are welcome! If you'd like to contribute, please follow these steps:

Fork the repository.

Create a new branch for your feature or bugfix.

Submit a pull request with a detailed description of your changes.

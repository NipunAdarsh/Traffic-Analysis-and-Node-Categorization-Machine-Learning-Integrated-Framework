# Traffic Analysis and Node Categorization
### Machine Learning Integrated Framework

A robust, real-time network monitoring and cybersecurity framework built with **Flask** and **Scikit-Learn**. This system integrates multiple machine learning paradigms to classify traffic, categorize network nodes, and detect anomalies in high-velocity data streams.

---

## 🚀 Key Features

*   **Real-time Traffic Dashboard**: Interactive monitoring with dynamic visualizations (Chart.js), malicious traffic gauges, and instant threat banners.
*   **Three-Tier ML Architecture**:
    *   **Traffic Classification**: Binary classification (Normal vs. Malicious).
    *   **Node Categorization**: Multi-class identification of device roles (Router, Server, IoT, etc.).
    *   **Anomaly Detection**: Statistical outlier identification for threat detection.
*   **Interactive Simulation Engine**: High-fidelity traffic simulation with start/stop controls and real-time API polling.
*   **Hybrid Inference Engine**: Robust logic that attempts model-based inference (`.joblib`) with a fallback to validated rule-based logic.
*   **Data Export & Reporting**: Server-side CSV generation for traffic logs and performance reporting.

---

## 🛠️ Technology Stack

| Component | Technology |
| :--- | :--- |
| **Backend** | Python, Flask, SQLAlchemy |
| **Machine Learning** | Scikit-Learn, Joblib |
| **Frontend** | Tailwind CSS, Chart.js, GSAP |

---

## 📦 Installation & Setup

### 1. Clone & Setup
```bash
git clone https://github.com/NipunAdarsh/Traffic-Analysis-and-Node-Categorization-Machine-Learning-Integrated-Framework.git
cd "Final Project Code"
python -m venv venv
source venv/Scripts/activate  # Windows
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```

---

## 🔑 Usage & Access

Login with the following administrator credentials:
*   **Username**: `admin`
*   **Password**: `admin123`

---

## 📂 Project Structure

```text
├── app.py              # Application Entry Point
├── models/             
│   ├── model_manager.py# ML Inference Engine
│   └── database.py     # Database Schema
├── routes/             
│   └── main.py         # App Logic & API Endpoints
├── templates/          # Modern UI Layouts
└── data_models/        # Pre-trained ML Models
```



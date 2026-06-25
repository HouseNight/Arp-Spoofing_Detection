# ARP Spoofing Detection

A machine learning-based system for detecting ARP (Address Resolution Protocol) spoofing attacks using XGBoost classification.

## Overview

ARP spoofing is a network attack technique where an attacker sends falsified ARP messages over a local network. This project aims to detect such attacks using machine learning, specifically leveraging XGBoost's powerful classification capabilities.

## Features

- **Machine Learning Based**: Uses XGBoost for high-accuracy classification of ARP spoofing attacks
- **Network Analysis**: Analyzes ARP traffic patterns to identify suspicious behavior
- **Binary Classification**: Classifies network traffic as legitimate or malicious
- **High Performance**: Optimized model for real-time detection capabilities

## Project Structure

```
Arp-Spoofing_Detection/
├── README.md
├── notebooks/              # Jupyter notebooks for analysis and experimentation
├── data/                   # Dataset files
├── models/                 # Trained XGBoost models
├── src/                    # Source code
└── requirements.txt        # Project dependencies
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/HouseNight/Arp-Spoofing_Detection.git
   cd Arp-Spoofing_Detection
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Required packages**:
   - xgboost
   - pandas
   - numpy
   - scikit-learn
   - jupyter (for notebook analysis)

## Usage

### Training the Model

```python
from src.model import train_arp_detector
from src.data import load_data

# Load and prepare data
X_train, X_test, y_train, y_test = load_data()

# Train the XGBoost model
model = train_arp_detector(X_train, y_train)

# Evaluate
accuracy = model.score(X_test, y_test)
print(f"Model Accuracy: {accuracy:.4f}")
```

### Making Predictions

```python
# Predict on new ARP traffic data
predictions = model.predict(X_new)
probabilities = model.predict_proba(X_new)
```

## Model Details

- **Algorithm**: XGBoost Classifier
- **Input Features**: ARP packet features and traffic patterns
- **Output**: Binary classification (Legitimate: 0, Spoofing: 1)
- **Model Evaluation**: Accuracy, Precision, Recall, F1-Score

## Dataset

The project uses ARP traffic datasets containing features extracted from network packets. The dataset includes both legitimate ARP communications and spoofed ARP packets.

### Data Features

- Source IP Address
- Destination IP Address
- Source MAC Address
- Destination MAC Address
- Protocol Information
- Temporal Features
- Traffic Statistics

## Results

The XGBoost model achieves strong performance in detecting ARP spoofing attacks with:
- High true positive rate for attack detection
- Low false positive rate for legitimate traffic
- Robust performance across different network conditions

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is open source and available under the MIT License.

## Author

**HouseNight** - [GitHub Profile](https://github.com/HouseNight)

## References

- XGBoost Documentation: https://xgboost.readthedocs.io/
- ARP Protocol: https://tools.ietf.org/html/rfc826
- Network Security Best Practices

## Getting Help

If you encounter issues or have questions:
1. Check the existing issues on GitHub
2. Create a new issue with a detailed description
3. Include relevant code snippets and error messages

---

**Last Updated**: 2026-06-25

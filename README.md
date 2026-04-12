# 🔐 API Security Scanner

A lightweight **API Security Testing Tool** built in Python that helps detect common API vulnerabilities such as **BOLA, CORS misconfiguration, injection issues, and missing rate limiting**.

This tool provides both:

- 🖥 **CLI (Terminal) Scanner**
- 🌐 **Interactive Streamlit Dashboard**

It is designed for **learning API security testing and basic vulnerability detection**.

---

# 🚀 Features

✔ Broken Object Level Authorization (BOLA) Detection  
✔ CORS Misconfiguration Detection  
✔ Injection Testing (basic payloads)  
✔ Missing Rate Limiting Detection  
✔ JWT Token Support (optional)  
✔ CLI-based scanning  
✔ Cyberpunk-style Streamlit Dashboard  
✔ Structured vulnerability reporting  

---

# 🛠 Technologies Used

- **Python**
- **Requests**
- **Streamlit**
- **JWT (PyJWT)**
- **Matplotlib**
- **Regex**
- **Hashing for response comparison**

---

# 📂 Project Structure

```
Api-security-scanner/
│
├── scanner/
│   ├── tests/
│   │   ├── bola.py
│   │   ├── cors.py
│   │   ├── injection.py
│   │   └── rate_limit.py
│   │
│   ├── http_client.py
│   └── report.py
│
├── app.py          # Streamlit dashboard
├── main.py         # CLI scanner
├── requirements.txt
└── README.md
```

---

# ⚙ Installation

### 1️⃣ Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/Api-security-scanner.git
```

### 2️⃣ Navigate to the project folder

```bash
cd Api-security-scanner
```

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

---

# ▶ Running the Scanner

## 🖥 Run CLI Version

```bash
python main.py --url https://example.com --endpoint /api/v1/users/1
```

With token:

```bash
python main.py --url https://example.com --endpoint /api/v1/users/1 --token YOUR_TOKEN
```

---

## 🌐 Run Dashboard Version

```bash
streamlit run app.py
```

Then open:

```
http://localhost:8501
```

---

# 🔍 Vulnerabilities Detected

### 1️⃣ Broken Object Level Authorization (BOLA)

The scanner modifies object IDs in endpoints and checks if unauthorized access is possible.

Example:

```
/api/users/1
/api/users/2
```

If both return valid responses, a potential **BOLA vulnerability** is flagged.

---

### 2️⃣ CORS Misconfiguration

Checks for dangerous configurations like:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

---

### 3️⃣ Injection Testing

Tests endpoints with common payloads such as:

```
' OR '1'='1
<script>alert(1)</script>
```

---

### 4️⃣ Missing Rate Limiting

Sends burst requests to detect whether the API enforces rate limiting.

If no `429 Too Many Requests` response is detected, a warning is generated.

---

# ⚠ Disclaimer

This tool is intended **only for educational and authorized security testing purposes**.

Do **NOT** scan systems without permission.

---

# 📸 Example

Example scan:

```
python main.py --url https://jsonplaceholder.typicode.com --endpoint /posts/1
```

Output:

```
Scanning endpoint...
No vulnerabilities detected.
```

---

# 🧠 Future Improvements

- GraphQL security testing
- JWT privilege escalation detection
- API endpoint discovery
- OpenAPI/Swagger integration
- Automated reporting (PDF/HTML)
- Advanced payload fuzzing

---

# 👨‍💻 Author

Developed by akarsh diwakar

GitHub:  
https://github.com/akarshdiwakar123

---

# ⭐ If You Like This Project

Give it a **star ⭐ on GitHub** to support the project.

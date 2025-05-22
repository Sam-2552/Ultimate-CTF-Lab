# Ultimate CTF Lab

A modern web application for managing and viewing song logs with an admin interface.

## Prerequisites

- Python 3.8 or higher
- UV Package Manager

## Installation

1. **Install UV Package Manager**

   For Windows (PowerShell):
   ```powershell
   (Invoke-WebRequest -Uri https://astral.sh/uv/install.ps1 -UseBasicParsing).Content | pwsh -Command -
   ```

   For Linux/macOS:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/Ultimate-CTF-Lab.git
   cd Ultimate-CTF-Lab
   ```

3. **Create and Activate Virtual Environment**
   ```bash
   uv venv
   # On Windows
   .venv\Scripts\activate
   # On Linux/macOS
   source .venv/bin/activate
   ```

4. **Install Dependencies**
   ```bash
   uv pip install -r requirements.txt
   ```

## Running the Application

1. **Start the Server**
   ```bash
   python server.py
   ```

2. **Access the Application**
   - Open your web browser
   - Navigate to `https://localhost:5000` (or the port specified in your configuration)

## Features

- Modern admin interface for viewing song logs
- Real-time search functionality
- Responsive design for all devices
- Secure user authentication
- Log management for add, edit, and delete operations

## Project Structure

```
Ultimate-CTF-Lab/
├── templates/
│   └── song_logs.html    # Admin logs interface
├── static/
│   └── lightTransp.png   # Application icon
├── server.py            # Main application server
├── requirements.txt     # Project dependencies
└── README.md           # This file
```


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers. 
# Find My Flipper - Web Interface

A user-friendly vibe-coded web interface for tracking your Flipper Zero devices using Apple's Find My network.

## Features

- 🗺️ **Interactive Map** - View Flipper locations on a real-time map
- 📁 **Key Management** - Easy upload and management of .keys files
- 🔐 **Secure Authentication** - Apple ID login with 2FA support
- 🔄 **Auto-Refresh** - Automatic location updates every 5 minutes
- 📊 **Location History** - View up to 24 hours of location reports
- 📱 **Responsive Design** - Works on desktop and mobile

## Prerequisites

1. **Flipper Zero** with [Find My Flipper](https://github.com/MatthewKuKanich/FindMyFlipper) app installed
2. **.keys file** generated using the Find My Flipper repository
3. **Apple ID** for authentication
4. **Anisette server** for spoofing
5. **[Docker Desktop](https://www.docker.com/products/docker-desktop/)** for the Anisette server
6. **Python** and **pip**

### Setting up Anisette Server

You'll need the anisette-v3-server running locally:

```bash
# Using Docker (recommended)
docker run -d --restart always --name anisette -p 6969:6969 dadoum/anisette-v3-server
```

## Installation

1. **Clone this repository:**

```bash
git clone https://github.com/civiltox/FindMyFlipper-Web
```

2. **Create a Python virtual environment:**

```bash
python -m venv venv
```

3. **Activate the virtual environment:**

```bash
# Linux/macOS
source venv/bin/activate
# Windows
venv\Scripts\activate.bat
```

4. **Install dependencies:**

```bash
pip install -r requirements.txt
```

## Usage

### 1. Start the server

```bash
python start.py
```

The server will start on `http://localhost:8000`

### 2. Login

- Navigate to `http://localhost:8000`
- You'll be redirected to the login page
- Enter your Apple ID credentials
- Enter the 6-digit code when prompted in your terminal

### 3. Upload your .keys file

- Click the upload area or drag your `.keys` file
- The file should be generated from the Find My Flipper app
- Multiple key files can be uploaded for tracking multiple devices

### 4. View locations

- Click "Refresh" to fetch latest location reports
- Locations auto-refresh every 5 minutes
- Click on a device to see detailed information
- Click markers on the map for quick info

## How It Works

1. **Authentication**: Uses pypush to authenticate with Apple's servers using SRP protocol
2. **Key Loading**: Reads .keys files containing device public/private key pairs
3. **Report Fetching**: Queries Apple's Find My network for location reports
4. **Decryption**: Decrypts location data using ECDH and AES-GCM
5. **Storage**: Saves reports to SQLite database for history
6. **Visualization**: Displays locations on interactive Leaflet map

## Authentication

- Authentication tokens are valid for ~24 hours
- Tokens are stored in `keys/auth.json`
- You'll be prompted to re-authenticate when expired
- 2FA is required each time you authenticate

## Security Notes

⚠️ **Important Security Considerations:**

- Keep your `.keys` files secure - they contain private keys
- Don't expose this web interface to the internet without additional security
- Consider using HTTPS if accessing remotely
- The `auth.json` file contains sensitive tokens - keep it private
- This is designed for local/personal use

## Troubleshooting

### "Authentication failed"
- Check your Apple ID credentials
- Ensure 2FA code is entered correctly
- Make sure anisette server is running

### "No reports found"
- Bring your Flipper near another Apple device
- Wait a few hours for reports to accumulate
- Lower the broadcast interval on the Find My Flipper app
- Increase transmission power on the Find My Flipper app

### "No key files found"
- Make sure your .keys file is uploaded
- Check that the file has the correct format
- Verify the file is in the `keys/` directory

### Anisette server not responding
```bash
# Check if docker container is running
docker ps | grep anisette

# Restart if needed
docker restart anisette
```

## API Endpoints

- `GET /` - Main dashboard (requires auth)
- `GET /login` - Login page
- `POST /login` - Authenticate with Apple ID
- `GET /logout` - Clear authentication
- `POST /api/upload_key` - Upload .keys file
- `GET /api/devices` - List tracked devices
- `GET /api/locations?hours=24` - Get location reports
- `GET /api/check_auth` - Check if authenticated

## Credits

Built on top of:
- [Find My Flipper](https://github.com/MatthewKuKanich/FindMyFlipper) by MatthewKuKanich
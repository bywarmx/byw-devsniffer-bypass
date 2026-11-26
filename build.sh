#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="/home/bywarrior/.local/jdk-17/bin:/home/bywarrior/Documentos/mexcript/.toolchains/android-sdk/build-tools/34.0.0:$PATH"
ANDROID_JAR="/home/bywarrior/Documentos/mexcript/.toolchains/android-sdk/platforms/android-35/android.jar"
AAPT="/home/bywarrior/Documentos/mexcript/.toolchains/android-sdk/build-tools/34.0.0/aapt"
D8="/home/bywarrior/Documentos/mexcript/.toolchains/android-sdk/build-tools/34.0.0/d8"
ZIPALIGN="/home/bywarrior/Documentos/mexcript/.toolchains/android-sdk/build-tools/34.0.0/zipalign"
APKSIGNER="/home/bywarrior/Documentos/mexcript/.toolchains/android-sdk/build-tools/34.0.0/apksigner"

mkdir -p "$DIR/build/classes_stubs" "$DIR/build/classes_module"

echo "[*] Compilando stubs Xposed..."
javac -d "$DIR/build/classes_stubs" $(find "$DIR/stubs" -name "*.java")

echo "[*] Compilando código del módulo..."
javac -cp "$DIR/build/classes_stubs:$ANDROID_JAR" -d "$DIR/build/classes_module" $(find "$DIR/src" -name "*.java")

echo "[*] Generando DEX..."
"$D8" --min-api 24 --classpath "$DIR/build/classes_stubs" --output "$DIR/build" $(find "$DIR/build/classes_module" -name "*.class")

echo "[*] Empaquetando recursos..."
"$AAPT" package -f -m \
    -M "$DIR/AndroidManifest.xml" \
    -S "$DIR/res" \
    -I "$ANDROID_JAR" \
    -F "$DIR/build/unsigned.apk"

cd "$DIR/build"
"$AAPT" add unsigned.apk classes.dex
"$AAPT" add unsigned.apk "$DIR/assets/xposed_init"

echo "[*] Alineando..."
"$ZIPALIGN" -p -f 4 "$DIR/build/unsigned.apk" "$DIR/build/aligned.apk"

if [ ! -f "$DIR/build/keystore.jks" ]; then
    keytool -genkeypair -v -keystore "$DIR/build/keystore.jks" -alias bywkey -keyalg RSA -keysize 2048 -validity 10000 -storepass 123456 -keypass 123456 -dname "CN=bywZero, OU=Dev, O=byw, L=MX, ST=MX, C=MX"
fi

mkdir -p "$DIR/release"
"$APKSIGNER" sign --ks "$DIR/build/keystore.jks" --ks-pass pass:123456 --key-pass pass:123456 --out "$DIR/release/byw_devsniffer_bypass.apk" "$DIR/build/aligned.apk"

echo "[+] Compilación exitosa: release/byw_devsniffer_bypass.apk"

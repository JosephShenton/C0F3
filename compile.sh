#!/bin/bash
echo "[*] Compiling C0F3.."
$(which xcodebuild) clean build CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" -sdk `xcrun --sdk iphoneos --show-sdk-path` -arch arm64
mv build/Release-iphoneos/C0F3.app C0F3.app
mkdir Payload
mv C0F3.app Payload/C0F3.app
echo "[*] Zipping into .ipa"
zip -r9 C0F3.ipa Payload/C0F3.app
rm -rf build Payload
echo "[*] Done! Install .ipa with Impactor"

import base64
import json
import argparse


# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"



def decode_base64(encoded_string):
    try:
        decoded_bytes = base64.b64decode(encoded_string)
        return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error decoding string: {e}"
    
def extract_powershell_commands(decoded_text):
    suspicious_keywords = [
        "powershell",
        "powershell.exe",
        "-enc",
        "-encodedcommand",
        "IEX",
        "Invoke-Expression",
        "Invoke-WebRequest",
        "New-Object",
        "Start-Process",
        ]
    found_items = []

    for keyword in suspicious_keywords:
        if keyword.lower() in decoded_text.lower():
            found_items.append(keyword)

    return found_items

def calculate_risk_score(indicators):
    score = 0

    high_risk = ["IEX", "Invoke-WebRequest", "-encodedcommand"]
    medium_risk = ["powershell", 'powershell.exe', "Start-Process"]
    low_risk = ["New-Object", "Invoke-Expression"]

    for item in indicators:
        if item in high_risk:
            score += 50
        elif item in medium_risk:
            score += 25
        elif item in low_risk:
            score += 10

    return score

def classify_severity(score):
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"
    
def colorize_severity(severity):
    if severity == "CRITICAL":
        return f"{RED}{severity}{RESET}"
    elif severity == "HIGH":
        return f"{RED}{severity}{RESET}"
    elif severity == "MEDIUM":
        return f"{YELLOW}{severity}{RESET}"
    else:
        return f"{GREEN}{severity}{RESET}"

    
def write_log(decoded_output, indicators, score, severity):
    with open("logs/decoder_log.txt", "a") as log_file:
        log_file.write("\n--- New Entry ---\n")
        log_file.write(f"Decoded Output: {decoded_output}\n")
        log_file.write(f"Indicators: {indicators}\n")
        log_file.write(f"Risk Score: {score}\n")
        log_file.write(f"Severity: {severity}\n")

def decode_file(file_path):
    try:
        with open(file_path, "r") as f:
            encoded_data = f.read().strip()
        return decode_base64(encoded_data)
    except Exception as e:
        return f"Error reading file: {e}"
    
def generate_json_output(decoded_output, indicators, score, severity):
    data = {
        "decoded_output": decoded_output,
        "indicators": indicators,
        "risk_score": score,
        "severity": severity
    }
    return json.dumps(data, indent=4)

def print_banner():
    print("\n========================================")
    print("   PowerShell Base64 Decoder - v1.0")
    print("   Created by Denarius")
    print("========================================\n")

def extract_indicators(decoded_output):
    indicators = []
    suspicious_commands = [
        "Invoke-WebRequest",
        "IEX",
        "Start-Process",
        "New-Object",
        "DownloadString",
        "Invoke-Expression"
    ]

    for cmd in suspicious_commands:
        if cmd.lower() in decoded_output.lower():
            indicators.append(cmd)

    return indicators

# ============================
# MAIN PROGRAM
# ============================

parser = argparse.ArgumentParser(
    description="Decode Base64-encoded PowerShell commands and classify risk."
)

parser.add_argument(
    "--string",
    help="Decode a Base64 string. Example: --string SQBFAFgAIAAiSW52b2tlLVdlYlJlcXVlc3Qi"
)

parser.add_argument(
    "--file",
    help="Decode a Base64 file. Example: --file samples/test_payload.txt"
)

parser.add_argument(
    "--quiet",
    action="store_true",
    help="Quiet mode: suppress banner and human-readable output."
)

parser.add_argument(
    "--json",
    action="store_true",
    help="JSON-only mode: output only JSON with no human-readable text."
)

parser.add_argument(
    "--out",
    help="Save JSON output to a file. Example: --out results.json"
)

parser.add_argument(
    "--folder",
    help="Decode all Base64 files in a folder. Example: --folder samples/"
)

args = parser.parse_args()   # ⭐ MUST COME BEFORE ANY USE OF args

import os

if args.folder:
    if not os.path.isdir(args.folder):
        print(f"Folder not found: {args.folder}")
        exit()

    files = os.listdir(args.folder)
    base64_files = [f for f in files if f.lower().endswith(".txt") or f.lower().endswith(".b64")]

    if not base64_files:
        print("No Base64 files found in the folder.")
        exit()

    results = []

    for filename in base64_files:
        filepath = os.path.join(args.folder, filename)

        try:
            decoded_output = decode_file(filepath)
        except Exception as e:
            print(f"Error decoding {filename}: {e}")
            continue

        indicators = extract_indicators(decoded_output)
        score = calculate_risk_score(indicators)
        severity = classify_severity(score)

        json_output = generate_json_output(decoded_output, indicators, score, severity)
        results.append((filename, json_output))

        if not args.quiet and not args.json:
            print(f"\n=== File: {filename} ===")
            print(decoded_output)
            print("\nIndicators:", indicators)
            print("Risk Score:", score)
            print("Severity:", severity)

        if args.out:
            out_path = os.path.join(args.out, filename + ".json")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json_output)

    if args.json:
        # JSON-only mode prints only JSON array
        print("[")
        for i, (_, json_output) in enumerate(results):
            print(json_output + ("," if i < len(results)-1 else ""))
        print("]")

    exit()
    
# Banner only prints if NOT quiet
if not args.quiet and not args.json:
    print_banner()

# Determine input mode
if args.string:
    decoded_output = decode_base64(args.string)

elif args.file:
    decoded_output = decode_file(args.file)

else:
    print("No input provided. Use --string or --file.")
    exit()

# Extract indicators and score
indicators = extract_indicators(decoded_output)
score = calculate_risk_score(indicators)
severity = classify_severity(score)

# Quiet mode suppresses human-readable output
if not args.quiet and not args.json:
    print("\nDecoded Output:\n")
    print(decoded_output)

    print("\nSuspicious Indicators Found:\n")
    if indicators:
        for item in indicators:
            print(f"- {item}")
    else:
        print("No suspicious PowerShell commands detected.")

    print(f"\nRisk Score: {score}")
    print(f"Severity Level: {colorize_severity(severity)}")

# Always write log
write_log(decoded_output, indicators, score, severity)

# Always print JSON output
json_output = generate_json_output(decoded_output, indicators, score, severity)

if not args.json:
    print("\nJSON Output:\n")

print(json_output)

# Save JSON to file if --out is used
if args.out:
    try:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(json_output)
        if not args.quiet and not args.json:
            print(f"\nSaved JSON output to: {args.out}")
    except Exception as e:
        print(f"Error saving file: {e}")









 
    
    
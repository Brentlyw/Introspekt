import os
import yara

def check_rule(rule_str):
    try:
        yara.compile(source=rule_str)
        return True
    except yara.SyntaxError:
        return False

def filter_valid_rules(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        lines = file.readlines()

    valid_rules = []
    current_rule = []
    in_rule = False

    for line in lines:
        if line.strip().startswith('rule'):
            in_rule = True
            if current_rule:
                rule_str = ''.join(current_rule)
                if check_rule(rule_str):
                    valid_rules.extend(current_rule)
                current_rule = []
        
        if in_rule:
            current_rule.append(line)
        
        if line.strip() == '}':
            in_rule = False
            rule_str = ''.join(current_rule)
            if check_rule(rule_str):
                valid_rules.extend(current_rule)
            current_rule = []

    # Handle case where the last rule in the file is invalid
    if current_rule:
        rule_str = ''.join(current_rule)
        if check_rule(rule_str):
            valid_rules.extend(current_rule)

    with open('filtered_' + file_path, 'w', encoding='utf-8') as file:
        file.writelines(valid_rules)

    print(f"Filtered rules have been written to 'filtered_{file_path}'")

def process_all_yar_files():
    for file_name in os.listdir('.'):
        if file_name.endswith('.yar'):
            print(f"Processing {file_name}...")
            filter_valid_rules(file_name)
            os.remove(file_name)
            print(f"{file_name} has been deleted.")

if __name__ == "__main__":
    process_all_yar_files()

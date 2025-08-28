import csv
import json
import re
from typing import Dict, Any, Tuple

class PIIDetectorRedactor:
    def __init__(self):
        # Standalone PII patterns
        self.patterns = {
            'phone': re.compile(r'^(\d{10})$'),
            'aadhar': re.compile(r'^(\d{12})$'),
            'passport': re.compile(r'^[A-PR-WY][A-Z0-9]{6,9}$'),
            'upi_id': re.compile(r'^[\w.-]+@[\w.-]+$')
        }
        
        # Combinatorial PII fields
        self.combinatorial_pii = ['name', 'email', 'address', 'device_id', 'ip_address']
    
    def is_standalone_pii(self, key: str, value: Any) -> bool:
        """Check if a key-value pair is standalone PII"""
        if not isinstance(value, str):
            return False
            
        if key == 'phone' and self.patterns['phone'].match(value):
            return True
        elif key == 'aadhar' and self.patterns['aadhar'].match(value):
            return True
        elif key == 'passport' and self.patterns['passport'].match(value):
            return True
        elif key == 'upi_id' and self.patterns['upi_id'].match(value):
            return True
            
        return False
    
    def mask_phone(self, phone: str) -> str:
        """Mask phone number: 9876543210 → 98XXXXXX10"""
        return phone[:2] + 'X' * 6 + phone[-2:]
    
    def mask_aadhar(self, aadhar: str) -> str:
        """Mask Aadhar number: 123456789012 → XXXX XXXX 9012"""
        return 'XXXX XXXX ' + aadhar[-4:]
    
    def mask_passport(self, passport: str) -> str:
        """Mask passport number: P1234567 → PXXXX567"""
        if len(passport) > 4:
            return passport[0] + 'X' * (len(passport)-4) + passport[-3:]
        return passport
    
    def mask_upi(self, upi: str) -> str:
        """Mask UPI ID: user@upi → u***@upi"""
        username, domain = upi.split('@', 1)
        if username.isdigit() and len(username) == 10:
            masked_username = self.mask_phone(username)
        else:
            masked_username = username[0] + '*' * max(3, len(username)-1)
        return f'{masked_username}@{domain}'
    
    def mask_email(self, email: str) -> str:
        """Mask email: john.doe@example.com → j***@example.com"""
        local_part, domain = email.split('@', 1)
        if len(local_part) > 1:
            masked_local = local_part[0] + '*' * max(3, len(local_part)-1)
        else:
            masked_local = local_part + '***'
        return f'{masked_local}@{domain}'
    
    def mask_name(self, name: str) -> str:
        """Mask name: John Doe → J*** D***"""
        parts = name.split()
        masked_parts = []
        for part in parts:
            if len(part) > 1:
                masked_parts.append(part[0] + '*' * max(3, len(part)-1))
            else:
                masked_parts.append(part + '***')
        return ' '.join(masked_parts)
    
    def mask_address(self, address: str) -> str:
        """Mask address: 123 Main St → 1** M*** S***"""
        words = address.split()
        masked_words = []
        for word in words:
            if word.isdigit():
                if len(word) > 2:
                    masked_words.append(word[0] + '*' * (len(word)-2) + word[-1])
                else:
                    masked_words.append('*' * len(word))
            else:
                if len(word) > 1:
                    masked_words.append(word[0] + '*' * max(3, len(word)-1))
                else:
                    masked_words.append(word + '***')
        return ' '.join(masked_words)
    
    def mask_device_id(self, device_id: str) -> str:
        """Mask device ID: DEV123456 → D*******6"""
        if len(device_id) > 2:
            return device_id[0] + '*' * (len(device_id)-2) + device_id[-1]
        return '*' * len(device_id)
    
    def mask_ip_address(self, ip: str) -> str:
        """Mask IP address: 192.168.1.1 → 192.168.*.*"""
        parts = ip.split('.')
        if len(parts) == 4:
            return f'{parts[0]}.{parts[1]}.*.*'
        return ip
    
    def process_record(self, record: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """Process a single record to detect and redact PII"""
        redacted_record = record.copy()
        has_standalone_pii = False
        combinatorial_fields_present = []
        
        # Check for standalone PII
        for key, value in record.items():
            if self.is_standalone_pii(key, value):
                has_standalone_pii = True
                if key == 'phone':
                    redacted_record[key] = self.mask_phone(value)
                elif key == 'aadhar':
                    redacted_record[key] = self.mask_aadhar(value)
                elif key == 'passport':
                    redacted_record[key] = self.mask_passport(value)
                elif key == 'upi_id':
                    redacted_record[key] = self.mask_upi(value)
            
            # Track combinatorial PII fields
            if key in self.combinatorial_pii and value:
                combinatorial_fields_present.append(key)
        
        # Check for combinatorial PII
        has_combinatorial_pii = len(combinatorial_fields_present) >= 2
        
        # Redact combinatorial PII if needed
        if has_combinatorial_pii:
            for key in combinatorial_fields_present:
                value = record[key]
                if key == 'name':
                    redacted_record[key] = self.mask_name(value)
                elif key == 'email':
                    redacted_record[key] = self.mask_email(value)
                elif key == 'address':
                    redacted_record[key] = self.mask_address(value)
                elif key == 'device_id':
                    redacted_record[key] = self.mask_device_id(value)
                elif key == 'ip_address':
                    redacted_record[key] = self.mask_ip_address(value)
        
        is_pii = has_standalone_pii or has_combinatorial_pii
        return redacted_record, is_pii

def main(input_file):
    detector = PIIDetectorRedactor()
    output_file = 'redacted_output.csv'
    
    with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
        reader = csv.DictReader(infile)
        writer = csv.DictWriter(outfile, fieldnames=['record_id', 'redacted_data_json', 'is_pii'])
        writer.writeheader()
        
        for row in reader:
            record_id = row['record_id']
            data_json = json.loads(row['data_json'])
            
            redacted_data, is_pii = detector.process_record(data_json)
            
            writer.writerow({
                'record_id': record_id,
                'redacted_data_json': json.dumps(redacted_data),
                'is_pii': is_pii
            })
    
    print(f"Processing complete. Output saved to {output_file}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("Usage: python pii_detector.py <input_csv_file>")
        sys.exit(1)
    
    main(sys.argv[1])
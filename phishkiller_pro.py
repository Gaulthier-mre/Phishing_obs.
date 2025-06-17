#!/usr/bin/env python3
import os
import re
import base64
import pickle
import logging
import warnings
from datetime import datetime
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# Configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
LOG_FILE = '/var/log/phishkiller.log'
WHITELIST = [
    'paypal.com', 'google.com', 'microsoft.com',
    'github.com', 'accounts.google.com',
    'instagram.com', 'facebook.com',
    'amazon.com', 'twitter.com'
]
PHISHING_KEYWORDS = {
    'urgent': 3, 'password': 3, 'verify': 2,
    'account': 2, 'security': 2, 'login': 3,
    'suspended': 4, 'compromised': 4,
    'hack': 4, 'locked': 3, 'action required': 3
}

warnings.filterwarnings("ignore", message="file_cache")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

class PhishDetector:
    def __init__(self):
        self.service = self.authenticate()
    
    def authenticate(self):
        creds = None
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
                
        return build('gmail', 'v1', credentials=creds)

    def extract_content(self, email_data):
        content = {
            'id': email_data['id'],
            'subject': 'No Subject',
            'sender': 'Unknown',
            'urls': set(),
            'body': ''
        }
        
        headers = email_data['payload']['headers']
        content['subject'] = next(
            (h['value'] for h in headers if h['name'] == 'Subject'),
            'No Subject'
        )
        content['sender'] = next(
            (h['value'] for h in headers if h['name'] == 'From'),
            'Unknown'
        )

        if 'parts' in email_data['payload']:
            for part in email_data['payload']['parts']:
                if part['mimeType'] == 'text/html':
                    try:
                        body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                        content['urls'].update(re.findall(r'href=[\'"]?([^\'" >]+)', body))
                        content['body'] = body[:500]
                    except Exception as e:
                        logging.warning(f"Decoding error: {str(e)}")
        
        return content

    def analyze_sender(self, sender):
        domain_match = re.search(r'@([a-zA-Z0-9.-]+)', sender)
        if not domain_match:
            return 5
            
        domain = domain_match.group(1).lower()
        
        # Whitelist prioritaire
        if any(trusted in domain for trusted in WHITELIST):
            return 0
            
        # Détection typosquatting
        if re.search(r'(paypa[1l]|g00gle|micr0soft|facebo0k)', domain):
            return 10
            
        return 3

    def is_phishing(self, email):
        total_score = self.analyze_sender(email['sender'])
        
        # Whitelist prioritaire
        if total_score == 0:
            return False
            
        content = email['subject'] + " " + email['body']
        content_lower = content.lower()
        
        # Analyse des mots-clés
        for kw, score in PHISHING_KEYWORDS.items():
            if kw in content_lower:
                total_score += score

        # Analyse des URLs
        for url in email['urls']:
            url_lower = url.lower()
            if not any(trusted in url_lower for trusted in WHITELIST):
                total_score += 3
                if re.search(r'(login|verify|account|secure)', url_lower):
                    total_score += 2
                if re.search(r'(paypal|google|microsoft|facebook)\.[^/]+\.(com|net)', url_lower):
                    total_score += 5

        # Réduction score pour codes 2FA
        if re.search(r'\b\d{6}\b', email['body']):
            total_score = max(0, total_score - 2)
            
        logging.info(f"Scan: {email['subject'][:30]}... | Score: {total_score}")
        return total_score >= 10

    def process_emails(self, max_results=20):
        try:
            results = self.service.users().messages().list(
                userId='me',
                maxResults=max_results,
                labelIds=['INBOX']
            ).execute()
            
            for msg in results.get('messages', []):
                try:
                    email = self.extract_content(
                        self.service.users().messages().get(
                            userId='me',
                            id=msg['id'],
                            format='full'
                        ).execute()
                    )
                    
                    if self.is_phishing(email):
                        logging.warning(f"PHISHING DETECTED: {email['subject']} | From: {email['sender']}")
                        self.service.users().messages().modify(
                            userId='me',
                            id=email['id'],
                            body={'removeLabelIds': ['INBOX'], 'addLabelIds': ['SPAM']}
                        ).execute()
                        
                except Exception as e:
                    logging.error(f"Error processing email: {str(e)}")
                    
        except Exception as e:
            logging.error(f"API Error: {str(e)}")

if __name__ == '__main__':
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            os.chmod(LOG_FILE, 0o644)
    
    logging.info("=== Starting PhishKiller ===")
    PhishDetector().process_emails()
    logging.info("=== Scan completed ===")

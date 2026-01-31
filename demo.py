"""
Demo script to test the DLP engine with sample inputs
"""
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from app.dlp_engine import decision_engine, pretty_print

def main():
    print("=" * 60)
    print("AI-Based DLP Engine - Demo")
    print("=" * 60)
    print()
    
    # Test cases - various sensitive data scenarios
    test_cases = [
        "My password is admin123",
        "Hello, how are you today?",
        "Please provide your API key for authentication",
        "Credit card number: 4532-1234-5678-9010",
        "SSN format: 123-45-6789",
        "This is a normal email: user@example.com",
        "GitHub token detected in source code",
        "Just a regular message with no sensitive data",
        "AWS credentials found in configuration",
        "Bearer token in authorization header",
        "My OTP code is 123456",
        "Database connection string detected",
        "Private key marker found in file",
        "Web hook endpoint found in logs"
    ]
    
    for i, text in enumerate(test_cases, 1):
        print(f"\n{'='*60}")
        print(f"Test Case {i}: {text}")
        print('='*60)
        result = decision_engine(text)
        pretty_print(result)
        print()
    
    print("\n" + "="*60)
    print("Demo completed!")
    print("="*60)

if __name__ == "__main__":
    main()

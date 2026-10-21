
import unittest
from detector import analyse_message


class TestDetector(unittest.TestCase):

    def test_otp_request_detected(self):
        result = analyse_message(
            "Please share your OTP to restore your account."
        )

        signal_names = [
            signal["type"] for signal in result["signals"]
        ]

        self.assertIn("otp_request", signal_names)

    def test_urgent_message_gets_high_risk(self):
        result = analyse_message(
            "URGENT: Your account will be blocked immediately. "
            "Share your OTP now."
        )

        self.assertEqual(result["risk_level"], "High")

    def test_ordinary_message_is_uncertain(self):
        result = analyse_message(
            "Your monthly bank statement is available."
        )

        self.assertEqual(result["risk_level"], "Uncertain")

    def test_prize_message_is_flagged(self):
        result = analyse_message(
            "You have won a prize. Claim your prize today!"
        )

        signal_names = [
            signal["type"] for signal in result["signals"]
        ]

        self.assertIn("suspicious_reward", signal_names)

    def test_url_is_extracted(self):
        result = analyse_message(
            "Please review this page: https://example.com"
        )

        self.assertIn("https://example.com", result["urls"])

    def test_empty_message_is_rejected(self):
        with self.assertRaises(ValueError):
            analyse_message("")

    def test_whitespace_message_is_rejected(self):
        with self.assertRaises(ValueError):
            analyse_message("   ")

    def test_otp_safety_warning_is_not_flagged_as_otp_request(self):
        result = analyse_message(
            "Never share your OTP with anyone."
        )

        signal_names = [
            signal["type"] for signal in result["signals"]
        ]

        self.assertNotIn("otp_request", signal_names)

    def test_direct_otp_request_is_detected(self):
        result = analyse_message(
            "Please share your OTP immediately."
        )

        signal_names = [
            signal["type"] for signal in result["signals"]
        ]

        self.assertIn("otp_request", signal_names)

    def test_urgent_money_transfer_is_detected(self):
        result = analyse_message(
            "Please transfer the money immediately to confirm payment."
        )

        signal_names = [
            signal["type"] for signal in result["signals"]
        ]

        self.assertIn("payment_request", signal_names)
        self.assertIn("urgent_language", signal_names)

    def test_ordinary_payment_confirmation_is_not_high_risk(self):
        result = analyse_message(
            "Your payment was received successfully. Thank you."
        )

        self.assertNotEqual(result["risk_level"], "High")




if __name__ == "__main__":
    unittest.main()

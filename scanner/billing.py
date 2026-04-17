import os
import stripe
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)

# You must set these in your production environment!
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_mock_key")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_mock_key")
PRO_PRICE_ID = os.getenv("PRO_PRICE_ID", "price_mock_pro_tier")

def create_checkout_session(user_id: int, user_email: str) -> str:
    """Create a Stripe Checkout Session URL for a user to upgrade to Pro tier."""
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price': PRO_PRICE_ID,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            customer_email=user_email,
            client_reference_id=str(user_id), # Link the stripe customer to DB user
            success_url=os.getenv("FRONTEND_URL", "http://localhost:8501") + "?payment=success",
            cancel_url=os.getenv("FRONTEND_URL", "http://localhost:8501") + "?payment=canceled",
        )
        return checkout_session.url
    except Exception as e:
        logger.error(f"Error creating checkout session: {e}")
        raise HTTPException(status_code=500, detail="Failed to create payment gateway.")

def verify_webhook_signature(payload: bytes, sig_header: str) -> stripe.Event:
    """Verify Stripe's signature to prevent fake webhook attacks."""
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        return event
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Invalid Stripe payload")
    except stripe.error.SignatureVerificationError as e:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")

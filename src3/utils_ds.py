from .model_ds import SignedMessage


def make_signed(m: int, s: int) -> SignedMessage:
    return SignedMessage(m, s)

import pytest

from language import detect_language

SAMPLES = {
    "en": "Dear customer, your account has been suspended. Please click here to verify your details, thank you.",
    "fr": "Bonjour, votre colis est bloqué. Merci de payer les frais pour que nous puissions le livrer rapidement.",
    "pt": "Olá, a sua conta foi bloqueada. Por favor confirme os seus dados para continuar com o serviço, obrigado.",
    "es": "Hola, su cuenta ha sido suspendida. Por favor confirme sus datos para continuar con el servicio, gracias.",
    "de": "Sehr geehrter Kunde, Ihr Konto wurde gesperrt. Bitte bestätigen Sie Ihre Daten, damit wir fortfahren können.",
    "it": "Gentile cliente, il suo conto è stato sospeso. La preghiamo di confermare i dati per continuare, grazie.",
    "nl": "Beste klant, uw account is geblokkeerd. Bevestig uw gegevens zodat wij de dienst kunnen voortzetten, bedankt.",
    "ha": "Sannu, an dakatar da asusun ku. Don Allah ku tabbatar da bayananku domin mu ci gaba da sabis, kuma nagode.",
    "ru": "Здравствуйте, ваш аккаунт заблокирован. Пожалуйста, подтвердите свои данные.",
    "uk": "Доброго дня, ваш обліковий запис заблоковано. Будь ласка, підтвердіть свої дані.",
    "ja": "お客様のアカウントは停止されました。こちらから確認してください。",
    "zh": "您的账户已被冻结，请点击这里验证您的信息。",
    "ar": "عزيزي العميل، تم تعليق حسابك. يرجى تأكيد بياناتك.",
}


@pytest.mark.parametrize("lang", sorted(SAMPLES))
def test_detects_the_language(lang):
    r = detect_language(SAMPLES[lang])
    assert r["code"] == lang and 0 < r["confidence"] <= 1


@pytest.mark.parametrize("text", ["", "Hi <NAME>, ok", "https://example.com/a?b=c", "1234 5678"])
def test_too_little_text_is_undetermined(text):
    assert detect_language(text) == {"code": "und", "confidence": 0.0}


def test_links_and_tags_do_not_count():
    r = detect_language("<URL> <EMAIL> https://www.example.com/the/and/you/your/for " * 5)
    assert r["code"] == "und"

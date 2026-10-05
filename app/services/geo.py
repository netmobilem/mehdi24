"""TiTaN Panel — country catalogue + flag helpers for the 'add server' modal."""

from __future__ import annotations

COUNTRIES: list[dict[str, str]] = [
    {"code": "IR", "fa": "ایران", "en": "Iran", "city": "Tehran"},
    {"code": "NL", "fa": "هلند", "en": "Netherlands", "city": "Amsterdam"},
    {"code": "DE", "fa": "آلمان", "en": "Germany", "city": "Frankfurt"},
    {"code": "US", "fa": "آمریکا", "en": "United States", "city": "Virginia"},
    {"code": "GB", "fa": "انگلستان", "en": "United Kingdom", "city": "London"},
    {"code": "FR", "fa": "فرانسه", "en": "France", "city": "Paris"},
    {"code": "TR", "fa": "ترکیه", "en": "Turkey", "city": "Istanbul"},
    {"code": "AE", "fa": "امارات", "en": "United Arab Emirates", "city": "Dubai"},
    {"code": "SG", "fa": "سنگاپور", "en": "Singapore", "city": "Singapore"},
    {"code": "JP", "fa": "ژاپن", "en": "Japan", "city": "Tokyo"},
    {"code": "IN", "fa": "هند", "en": "India", "city": "Mumbai"},
    {"code": "CA", "fa": "کانادا", "en": "Canada", "city": "Toronto"},
    {"code": "FI", "fa": "فینلاند", "en": "Finland", "city": "Helsinki"},
    {"code": "SE", "fa": "سوئد", "en": "Sweden", "city": "Stockholm"},
    {"code": "PL", "fa": "لهستان", "en": "Poland", "city": "Warsaw"},
    {"code": "RU", "fa": "روسیه", "en": "Russia", "city": "Moscow"},
    {"code": "AT", "fa": "اتریش", "en": "Austria", "city": "Vienna"},
    {"code": "CH", "fa": "سوئیس", "en": "Switzerland", "city": "Zurich"},
    {"code": "ES", "fa": "اسپانیا", "en": "Spain", "city": "Madrid"},
    {"code": "IT", "fa": "ایتالیا", "en": "Italy", "city": "Milan"},
    {"code": "RO", "fa": "رومانی", "en": "Romania", "city": "Bucharest"},
    {"code": "BG", "fa": "بلغارستان", "en": "Bulgaria", "city": "Sofia"},
    {"code": "UA", "fa": "اوکراین", "en": "Ukraine", "city": "Kyiv"},
    {"code": "LT", "fa": "لیتوانی", "en": "Lithuania", "city": "Vilnius"},
    {"code": "LV", "fa": "لتونی", "en": "Latvia", "city": "Riga"},
    {"code": "EE", "fa": "استونی", "en": "Estonia", "city": "Tallinn"},
    {"code": "CZ", "fa": "چک", "en": "Czechia", "city": "Prague"},
    {"code": "NO", "fa": "نروژ", "en": "Norway", "city": "Oslo"},
    {"code": "DK", "fa": "دانمارک", "en": "Denmark", "city": "Copenhagen"},
    {"code": "IE", "fa": "ایرلند", "en": "Ireland", "city": "Dublin"},
    {"code": "BE", "fa": "بلژیک", "en": "Belgium", "city": "Brussels"},
    {"code": "KR", "fa": "کره جنوبی", "en": "South Korea", "city": "Seoul"},
    {"code": "HK", "fa": "هنگ‌کنگ", "en": "Hong Kong", "city": "Hong Kong"},
    {"code": "AU", "fa": "استرالیا", "en": "Australia", "city": "Sydney"},
    {"code": "BR", "fa": "برزیل", "en": "Brazil", "city": "São Paulo"},
    {"code": "ZA", "fa": "آفریقای جنوبی", "en": "South Africa", "city": "Johannesburg"},
    {"code": "QA", "fa": "قطر", "en": "Qatar", "city": "Doha"},
    {"code": "OM", "fa": "عمان", "en": "Oman", "city": "Muscat"},
    {"code": "AM", "fa": "ارمنستان", "en": "Armenia", "city": "Yerevan"},
    {"code": "GE", "fa": "گرجستان", "en": "Georgia", "city": "Tbilisi"},
]

CITY_PRESETS: dict[str, list[str]] = {
    "IR": ["Tehran", "Mashhad", "Isfahan", "Tabriz", "Shiraz"],
    "NL": ["Amsterdam", "Rotterdam", "Eindhoven"],
    "DE": ["Frankfurt", "Berlin", "Nuremberg", "Falkenstein"],
    "US": ["Virginia", "Los Angeles", "New York", "Dallas", "Seattle", "Miami"],
    "GB": ["London", "Manchester"],
    "FR": ["Paris", "Marseille", "Roubaix"],
    "TR": ["Istanbul", "Ankara", "Izmir"],
    "AE": ["Dubai", "Abu Dhabi"],
    "SG": ["Singapore"],
    "JP": ["Tokyo", "Osaka"],
    "IN": ["Mumbai", "Delhi", "Chennai"],
    "CA": ["Toronto", "Montreal", "Vancouver"],
    "FI": ["Helsinki", "Espoo"],
    "SE": ["Stockholm", "Gothenburg"],
    "PL": ["Warsaw", "Krakow"],
    "RU": ["Moscow", "Saint Petersburg"],
}


def flag_for(code: str) -> str:
    """Regional-indicator flag emoji from a 2-letter country code."""
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return chr(0x1F1E6 + ord(code[0]) - 65) + chr(0x1F1E6 + ord(code[1]) - 65)


def country_name(code: str, fa: bool = True) -> str:
    for entry in COUNTRIES:
        if entry["code"] == code.upper():
            return entry["fa"] if fa else entry["en"]
    return code.upper()


def default_city(code: str) -> str:
    for entry in COUNTRIES:
        if entry["code"] == code.upper():
            return entry["city"]
    return ""


def cities_for(code: str) -> list[str]:
    return CITY_PRESETS.get(code.upper(), [default_city(code)] if default_city(code) else [])
